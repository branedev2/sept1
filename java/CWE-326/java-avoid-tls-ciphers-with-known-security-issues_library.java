import java.net.URL;
import java.net.HttpURLConnection;
import java.security.KeyStore;
import java.security.SecureRandom;
import javax.net.ssl.*;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.ssl.SSLContextBuilder;

import okhttp3.OkHttpClient;
import okhttp3.ConnectionSpec;
import okhttp3.TlsVersion;
import okhttp3.CipherSuite;

import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.JksOptions;

import io.undertow.Undertow;
import io.undertow.Handlers;
import io.undertow.server.HttpHandler;
import io.undertow.server.handlers.PathHandler;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import com.squareup.okhttp.ConnectionSpec;

import org.glassfish.grizzly.ssl.SSLContextConfigurator;
import org.glassfish.grizzly.ssl.SSLEngineConfigurator;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.grizzly.http.server.NetworkListener;

import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;

import play.server.Server;
import play.server.SSLEngineProvider;

import ratpack.server.ServerConfig;
import ratpack.server.RatpackServer;

import com.google.api.client.http.javanet.NetHttpTransport;

import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.catalina.connector.Connector;

// Security Issue: Using TLS cipher suites with known security issues

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    try {
        // Using Java's HttpsURLConnection with insecure cipher suites
        URL url = new URL("https://example.com");
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        System.setProperty("https.cipherSuites", "TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA");
        
        connection.setSSLSocketFactory(socketFactory);
        connection.connect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    try {
        // Using Apache HttpClient with weak cipher suites
        SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
        sslContextBuilder.loadTrustMaterial(null, (chain, authType) -> true);
        
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(
            sslContextBuilder.build(),
            new String[]{"TLSv1.2"},
            new String[]{"TLS_DH_anon_WITH_AES_128_CBC_SHA", "TLS_DH_anon_WITH_AES_256_CBC_SHA"},
            SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        
        HttpClient httpClient = HttpClients.custom()
            .setSSLSocketFactory(sslConnectionSocketFactory)
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    // Using OkHttp3 with insecure cipher suites
    // ruleid: java-avoid-tls-ciphers-with-known-security-issues
    ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        .tlsVersions(TlsVersion.TLS_1_2)
        .cipherSuites(
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA
        )
        .build();

    OkHttpClient client = new OkHttpClient.Builder()
        .connectionSpecs(Collections.singletonList(spec))
        .build();
}

public void bad_case_4() {
    try {
        // Using Spring Boot server with weak cipher suites
        WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> customizer = factory -> {
            Ssl ssl = new Ssl();
            ssl.setEnabled(true);
            ssl.setKeyStore("keystore.jks");
            ssl.setKeyStorePassword("password");
            
            // ruleid: java-avoid-tls-ciphers-with-known-security-issues
            ssl.setCiphers(new String[]{
                "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_RSA_WITH_AES_128_CBC_SHA"
            });
            
            factory.setSsl(ssl);
        };
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // Using AWS SDK with insecure TLS configuration
    ClientConfiguration clientConfig = new ClientConfiguration();
    
    // ruleid: java-avoid-tls-ciphers-with-known-security-issues
    clientConfig.setCipherSuites("TLS_RSA_WITH_AES_128_CBC_SHA");
    
    AmazonS3ClientBuilder.standard()
        .withClientConfiguration(clientConfig)
        .build();
}

public void bad_case_6() {
    // Using Vert.x with insecure cipher suites
    Vertx vertx = Vertx.vertx();
    HttpServerOptions options = new HttpServerOptions()
        .setSsl(true)
        .setKeyStoreOptions(new JksOptions()
            .setPath("keystore.jks")
            .setPassword("password"));
    
    // ruleid: java-avoid-tls-ciphers-with-known-security-issues
    options.addEnabledCipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA");
    options.addEnabledCipherSuite("SSL_RSA_WITH_3DES_EDE_CBC_SHA");
    
    HttpServer server = vertx.createHttpServer(options);
    server.listen(8443);
}

public void bad_case_7() {
    // Using Undertow with insecure cipher suites
    try {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        String[] cipherSuites = {"TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"};
        
        Undertow server = Undertow.builder()
            .addHttpsListener(8443, "localhost", sslContext)
            .setServerOption(UndertowOptions.ENABLED_CIPHER_SUITES, String.join(",", cipherSuites))
            .setHandler(Handlers.path().addPrefixPath("/api", exchange -> {
                exchange.getResponseSender().send("Hello World");
            }))
            .build();
        server.start();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    // Using Jetty with insecure cipher suites
    Server server = new Server();
    ServerConnector connector = new ServerConnector(server);
    connector.setPort(8080);
    
    SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
    sslContextFactory.setKeyStorePath("keystore.jks");
    sslContextFactory.setKeyStorePassword("password");
    
    // ruleid: java-avoid-tls-ciphers-with-known-security-issues
    sslContextFactory.setIncludeCipherSuites(
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
    );
    
    ServerConnector sslConnector = new ServerConnector(server, sslContextFactory);
    sslConnector.setPort(8443);
    
    server.addConnector(sslConnector);
}

public void bad_case_9() {
    // Using OkHttp (older version) with insecure cipher suites
    // ruleid: java-avoid-tls-ciphers-with-known-security-issues
    com.squareup.okhttp.ConnectionSpec spec = new com.squareup.okhttp.ConnectionSpec.Builder(true)
        .cipherSuites(
            com.squareup.okhttp.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            com.squareup.okhttp.CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA
        )
        .tlsVersions(com.squareup.okhttp.TlsVersion.TLS_1_2)
        .build();
    
    com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
    client.setConnectionSpecs(Collections.singletonList(spec));
}

public void bad_case_10() {
    // Using Grizzly HTTP Server with insecure cipher suites
    SSLContextConfigurator sslContextConfigurator = new SSLContextConfigurator();
    sslContextConfigurator.setKeyStoreFile("keystore.jks");
    sslContextConfigurator.setKeyStorePass("password");
    
    SSLEngineConfigurator sslEngineConfigurator = new SSLEngineConfigurator(sslContextConfigurator);
    sslEngineConfigurator.setClientMode(false);
    sslEngineConfigurator.setNeedClientAuth(false);
    
    // ruleid: java-avoid-tls-ciphers-with-known-security-issues
    sslEngineConfigurator.setEnabledCipherSuites(new String[]{
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
    });
    
    HttpServer server = HttpServer.createSimpleServer();
    NetworkListener listener = new NetworkListener("ssl", "localhost", 8443);
    listener.setSecure(true);
    listener.setSSLEngineConfig(sslEngineConfigurator);
    server.addListener(listener);
}

public void bad_case_11() {
    // Using RESTEasy client with insecure cipher suites
    // ruleid: java-avoid-tls-ciphers-with-known-security-issues
    ResteasyClientBuilder clientBuilder = new ResteasyClientBuilder()
        .enableCipherSuites("TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA")
        .hostnameVerification(ResteasyClientBuilder.HostnameVerificationPolicy.ANY);
    
    javax.ws.rs.client.Client client = clientBuilder.build();
}

public void bad_case_12() {
    // Using Play Framework with insecure cipher suites
    try {
        // Custom SSLEngineProvider for Play Framework
        SSLEngineProvider engineProvider = new SSLEngineProvider() {
            @Override
            public SSLEngine createSSLEngine() {
                try {
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(null, null, new SecureRandom());
                    SSLEngine engine = sslContext.createSSLEngine();
                    
                    // ruleid: java-avoid-tls-ciphers-with-known-security-issues
                    engine.setEnabledCipherSuites(new String[]{
                        "TLS_RSA_WITH_AES_128_CBC_SHA",
                        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
                    });
                    
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13() {
    // Using Ratpack with insecure cipher suites
    try {
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        RatpackServer.start(server -> server
            .serverConfig(config -> config
                .ssl(SSLContexts.custom()
                    .setProtocol("TLS")
                    .build(), 
                    sslContext -> {
                        SSLEngine engine = sslContext.createSSLEngine();
                        engine.setEnabledCipherSuites(new String[]{
                            "TLS_RSA_WITH_AES_128_CBC_SHA",
                            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
                        });
                        return engine;
                    }
                )
            )
            .handlers(chain -> chain
                .get(ctx -> ctx.render("Hello World!"))
            )
        );
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    // Using Google HTTP Client with insecure cipher suites
    try {
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        System.setProperty("https.cipherSuites", 
            "TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
        
        NetHttpTransport transport = new NetHttpTransport.Builder()
            .trustCertificates(KeyStore.getInstance(KeyStore.getDefaultType()))
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15() {
    // Using Tomcat with insecure cipher suites
    Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
    connector.setPort(8443);
    connector.setSecure(true);
    connector.setScheme("https");
    
    SSLHostConfig sslHostConfig = new SSLHostConfig();
    
    // ruleid: java-avoid-tls-ciphers-with-known-security-issues
    sslHostConfig.setCiphers("TLS_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
    
    connector.addSslHostConfig(sslHostConfig);
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() {
    try {
        // Using Java's HttpsURLConnection with secure cipher suites
        URL url = new URL("https://example.com");
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        System.setProperty("https.cipherSuites", 
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        
        connection.setSSLSocketFactory(socketFactory);
        connection.connect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    try {
        // Using Apache HttpClient with secure cipher suites
        SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
        sslContextBuilder.loadTrustMaterial(null, (chain, authType) -> true);
        
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(
            sslContextBuilder.build(),
            new String[]{"TLSv1.2"},
            new String[]{
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            },
            SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        
        HttpClient httpClient = HttpClients.custom()
            .setSSLSocketFactory(sslConnectionSocketFactory)
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    // Using OkHttp3 with secure cipher suites
    // ok: java-avoid-tls-ciphers-with-known-security-issues
    ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        .tlsVersions(TlsVersion.TLS_1_2)
        .cipherSuites(
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        )
        .build();

    OkHttpClient client = new OkHttpClient.Builder()
        .connectionSpecs(Collections.singletonList(spec))
        .build();
}

public void good_case_4() {
    try {
        // Using Spring Boot server with secure cipher suites
        WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> customizer = factory -> {
            Ssl ssl = new Ssl();
            ssl.setEnabled(true);
            ssl.setKeyStore("keystore.jks");
            ssl.setKeyStorePassword("password");
            
            // ok: java-avoid-tls-ciphers-with-known-security-issues
            ssl.setCiphers(new String[]{
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            });
            
            factory.setSsl(ssl);
        };
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    // Using AWS SDK with secure TLS configuration
    ClientConfiguration clientConfig = new ClientConfiguration();
    
    // ok: java-avoid-tls-ciphers-with-known-security-issues
    clientConfig.setCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    
    AmazonS3ClientBuilder.standard()
        .withClientConfiguration(clientConfig)
        .build();
}

public void good_case_6() {
    // Using Vert.x with secure cipher suites
    Vertx vertx = Vertx.vertx();
    HttpServerOptions options = new HttpServerOptions()
        .setSsl(true)
        .setKeyStoreOptions(new JksOptions()
            .setPath("keystore.jks")
            .setPassword("password"));
    
    // ok: java-avoid-tls-ciphers-with-known-security-issues
    options.addEnabledCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    options.addEnabledCipherSuite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
    options.addEnabledCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    
    HttpServer server = vertx.createHttpServer(options);
    server.listen(8443);
}

public void good_case_7() {
    // Using Undertow with secure cipher suites
    try {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        String[] cipherSuites = {
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        };
        
        Undertow server = Undertow.builder()
            .addHttpsListener(8443, "localhost", sslContext)
            .setServerOption(UndertowOptions.ENABLED_CIPHER_SUITES, String.join(",", cipherSuites))
            .setHandler(Handlers.path().addPrefixPath("/api", exchange -> {
                exchange.getResponseSender().send("Hello World");
            }))
            .build();
        server.start();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    // Using Jetty with secure cipher suites
    Server server = new Server();
    ServerConnector connector = new ServerConnector(server);
    connector.setPort(8080);
    
    SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
    sslContextFactory.setKeyStorePath("keystore.jks");
    sslContextFactory.setKeyStorePassword("password");
    
    // ok: java-avoid-tls-ciphers-with-known-security-issues
    sslContextFactory.setIncludeCipherSuites(
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    );
    
    ServerConnector sslConnector = new ServerConnector(server, sslContextFactory);
    sslConnector.setPort(8443);
    
    server.addConnector(sslConnector);
}

public void good_case_9() {
    // Using OkHttp (older version) with secure cipher suites
    // ok: java-avoid-tls-ciphers-with-known-security-issues
    com.squareup.okhttp.ConnectionSpec spec = new com.squareup.okhttp.ConnectionSpec.Builder(true)
        .cipherSuites(
            com.squareup.okhttp.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            com.squareup.okhttp.CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        )
        .tlsVersions(com.squareup.okhttp.TlsVersion.TLS_1_2)
        .build();
    
    com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
    client.setConnectionSpecs(Collections.singletonList(spec));
}

public void good_case_10() {
    // Using Grizzly HTTP Server with secure cipher suites
    SSLContextConfigurator sslContextConfigurator = new SSLContextConfigurator();
    sslContextConfigurator.setKeyStoreFile("keystore.jks");
    sslContextConfigurator.setKeyStorePass("password");
    
    SSLEngineConfigurator sslEngineConfigurator = new SSLEngineConfigurator(sslContextConfigurator);
    sslEngineConfigurator.setClientMode(false);
    sslEngineConfigurator.setNeedClientAuth(false);
    
    // ok: java-avoid-tls-ciphers-with-known-security-issues
    sslEngineConfigurator.setEnabledCipherSuites(new String[]{
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    });
    
    HttpServer server = HttpServer.createSimpleServer();
    NetworkListener listener = new NetworkListener("ssl", "localhost", 8443);
    listener.setSecure(true);
    listener.setSSLEngineConfig(sslEngineConfigurator);
    server.addListener(listener);
}

public void good_case_11() {
    // Using RESTEasy client with secure cipher suites
    // ok: java-avoid-tls-ciphers-with-known-security-issues
    ResteasyClientBuilder clientBuilder = new ResteasyClientBuilder()
        .enableCipherSuites(
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        )
        .hostnameVerification(ResteasyClientBuilder.HostnameVerificationPolicy.WILDCARD);
    
    javax.ws.rs.client.Client client = clientBuilder.build();
}

public void good_case_12() {
    // Using Play Framework with secure cipher suites
    try {
        // Custom SSLEngineProvider for Play Framework
        SSLEngineProvider engineProvider = new SSLEngineProvider() {
            @Override
            public SSLEngine createSSLEngine() {
                try {
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(null, null, new SecureRandom());
                    SSLEngine engine = sslContext.createSSLEngine();
                    
                    // ok: java-avoid-tls-ciphers-with-known-security-issues
                    engine.setEnabledCipherSuites(new String[]{
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                    });
                    
                    return engine;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13() {
    // Using Ratpack with secure cipher suites
    try {
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        RatpackServer.start(server -> server
            .serverConfig(config -> config
                .ssl(SSLContexts.custom()
                    .setProtocol("TLS")
                    .build(), 
                    sslContext -> {
                        SSLEngine engine = sslContext.createSSLEngine();
                        engine.setEnabledCipherSuites(new String[]{
                            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                        });
                        return engine;
                    }
                )
            )
            .handlers(chain -> chain
                .get(ctx -> ctx.render("Hello World!"))
            )
        );
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14() {
    // Using Google HTTP Client with secure cipher suites
    try {
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        System.setProperty("https.cipherSuites", 
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        
        NetHttpTransport transport = new NetHttpTransport.Builder()
            .trustCertificates(KeyStore.getInstance(KeyStore.getDefaultType()))
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15() {
    // Using Tomcat with secure cipher suites
    Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
    connector.setPort(8443);
    connector.setSecure(true);
    connector.setScheme("https");
    
    SSLHostConfig sslHostConfig = new SSLHostConfig();
    
    // ok: java-avoid-tls-ciphers-with-known-security-issues
    sslHostConfig.setCiphers(
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    );
    
    connector.addSslHostConfig(sslHostConfig);
}