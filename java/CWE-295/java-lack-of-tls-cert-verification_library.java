import java.io.IOException;
import java.net.URL;
import java.net.HttpURLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

import com.squareup.okhttp.ConnectionSpec;
import com.squareup.okhttp.TlsVersion;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.services.s3.AmazonS3Client;

import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.net.JksOptions;

import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClientConfig;

import com.ning.http.client.AsyncHttpClientConfig;

import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.services.s3.S3Client;

import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.JerseyClientBuilder;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

// Security Issue: Lack of TLS Certificate Verification in Java Applications

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() throws Exception {
    // Using javax.net.ssl with a trust manager that accepts all certificates
    SSLContext sslContext = SSLContext.getInstance("TLS");
    
    // ruleid: java-lack-of-tls-cert-verification
    TrustManager[] trustAllCerts = new TrustManager[] { 
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }
    };
    
    sslContext.init(null, trustAllCerts, new SecureRandom());
    HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    
    URL url = new URL("https://example.com");
    HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
    connection.connect();
}

public void bad_case_2() throws Exception {
    // Using Apache HttpClient with NoopHostnameVerifier
    SSLContextBuilder builder = new SSLContextBuilder();
    
    // ruleid: java-lack-of-tls-cert-verification
    builder.loadTrustMaterial(null, new TrustAllStrategy());
    
    SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
        builder.build(), NoopHostnameVerifier.INSTANCE);
    
    HttpClient client = HttpClients.custom()
        .setSSLSocketFactory(sslsf)
        .build();
    
    HttpGet request = new HttpGet("https://example.com");
    client.execute(request);
}

public void bad_case_3() throws Exception {
    // Using OkHttp3 with a trust manager that accepts all certificates
    OkHttpClient.Builder builder = new OkHttpClient.Builder();
    
    TrustManager[] trustAllCerts = new TrustManager[] {
        new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            
            @Override
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }
    };
    
    SSLContext sslContext = SSLContext.getInstance("TLS");
    // ruleid: java-lack-of-tls-cert-verification
    sslContext.init(null, trustAllCerts, new SecureRandom());
    
    builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0])
           .hostnameVerifier((hostname, session) -> true);
    
    OkHttpClient client = builder.build();
    Request request = new Request.Builder()
        .url("https://example.com")
        .build();
    
    Response response = client.newCall(request).execute();
}

public void bad_case_4() throws Exception {
    // Using Spring RestTemplate with insecure SSL configuration
    SSLContext sslContext = SSLContext.getInstance("TLS");
    
    // ruleid: java-lack-of-tls-cert-verification
    sslContext.init(null, new TrustManager[] { 
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }
    }, null);
    
    HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
    
    HttpClient httpClient = HttpClients.custom()
        .setSSLContext(sslContext)
        .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
        .build();
    
    requestFactory.setHttpClient(httpClient);
    RestTemplate restTemplate = new RestTemplate(requestFactory);
    
    restTemplate.getForObject("https://example.com", String.class);
}

public void bad_case_5() throws Exception {
    // Using Jetty HttpClient with insecure SSL configuration
    SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
    
    // ruleid: java-lack-of-tls-cert-verification
    sslContextFactory.setTrustAll(true);
    
    org.eclipse.jetty.client.HttpClient client = new org.eclipse.jetty.client.HttpClient(sslContextFactory);
    client.start();
    
    client.newRequest("https://example.com")
        .send();
}

public void bad_case_6() throws Exception {
    // Using Retrofit with OkHttp and insecure SSL configuration
    OkHttpClient.Builder builder = new OkHttpClient.Builder();
    
    // ruleid: java-lack-of-tls-cert-verification
    builder.hostnameVerifier((hostname, session) -> true);
    
    SSLContext sslContext = SSLContext.getInstance("TLS");
    TrustManager[] trustAllCerts = new TrustManager[] {
        new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }
    };
    sslContext.init(null, trustAllCerts, new SecureRandom());
    builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
    
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl("https://example.com/")
        .client(builder.build())
        .addConverterFactory(GsonConverterFactory.create())
        .build();
}

public void bad_case_7() throws Exception {
    // Using AWS SDK with disabled certificate checking
    ClientConfiguration clientConfig = new ClientConfiguration();
    
    // ruleid: java-lack-of-tls-cert-verification
    clientConfig.setSSLContext(createInsecureSSLContext());
    
    AmazonS3Client s3Client = new AmazonS3Client(clientConfig);
    s3Client.listBuckets();
    
    // Helper method to create insecure SSL context
    SSLContext createInsecureSSLContext() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
        }, new SecureRandom());
        return sslContext;
    }
}

public void bad_case_8() throws Exception {
    // Using Google API Client with insecure HTTP transport
    // ruleid: java-lack-of-tls-cert-verification
    NetHttpTransport.Builder builder = new NetHttpTransport.Builder()
        .doNotValidateCertificate();
    
    NetHttpTransport transport = builder.build();
    
    // Use the transport for API calls
    // This would typically be used with a service like:
    // new Drive.Builder(transport, jsonFactory, credential).build();
}

public void bad_case_9() throws Exception {
    // Using AsyncHttpClient with insecure SSL configuration
    DefaultAsyncHttpClientConfig.Builder configBuilder = new DefaultAsyncHttpClientConfig.Builder();
    
    // ruleid: java-lack-of-tls-cert-verification
    configBuilder.setUseInsecureTrustManager(true);
    
    AsyncHttpClient client = new DefaultAsyncHttpClient(configBuilder.build());
    client.prepareGet("https://example.com").execute();
}

public void bad_case_10() throws Exception {
    // Using Jersey Client with insecure SSL configuration
    ClientConfig clientConfig = new ClientConfig();
    
    SSLContext sslContext = SSLContext.getInstance("TLS");
    // ruleid: java-lack-of-tls-cert-verification
    sslContext.init(null, new TrustManager[] {
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }
    }, new SecureRandom());
    
    javax.ws.rs.client.Client client = JerseyClientBuilder.newBuilder()
        .sslContext(sslContext)
        .hostnameVerifier((hostname, session) -> true)
        .build();
    
    client.target("https://example.com").request().get();
}

public void bad_case_11() throws Exception {
    // Using Azure SDK with insecure HTTP client
    // ruleid: java-lack-of-tls-cert-verification
    com.azure.core.http.HttpClient httpClient = new NettyAsyncHttpClientBuilder()
        .disableCertificateValidation()
        .build();
    
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .endpoint("https://example.blob.core.windows.net/")
        .httpClient(httpClient)
        .buildClient();
}

public void bad_case_12() throws Exception {
    // Using Vert.x HTTP client with insecure SSL options
    Vertx vertx = Vertx.vertx();
    
    // ruleid: java-lack-of-tls-cert-verification
    HttpClientOptions options = new HttpClientOptions()
        .setSsl(true)
        .setTrustAll(true)
        .setVerifyHost(false);
    
    io.vertx.core.http.HttpClient client = vertx.createHttpClient(options);
    client.getNow(443, "example.com", "/", response -> {
        System.out.println("Received response with status code " + response.statusCode());
    });
}

public void bad_case_13() throws Exception {
    // Using Ning AsyncHttpClient with insecure SSL configuration
    com.ning.http.client.AsyncHttpClientConfig.Builder configBuilder = new com.ning.http.client.AsyncHttpClientConfig.Builder();
    
    // ruleid: java-lack-of-tls-cert-verification
    configBuilder.setAcceptAnyCertificate(true);
    
    com.ning.http.client.AsyncHttpClient client = new com.ning.http.client.AsyncHttpClient(configBuilder.build());
    client.prepareGet("https://example.com").execute();
}

public void bad_case_14() throws Exception {
    // Using AWS SDK v2 with insecure Apache HTTP client
    // ruleid: java-lack-of-tls-cert-verification
    SdkHttpClient httpClient = ApacheHttpClient.builder()
        .tlsTrustManagersProvider(() -> new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
        })
        .build();
    
    S3Client s3 = S3Client.builder()
        .httpClient(httpClient)
        .build();
}

public void bad_case_15() throws Exception {
    // Using Netty SslContext with insecure trust manager
    // ruleid: java-lack-of-tls-cert-verification
    SslContext sslContext = SslContextBuilder.forClient()
        .trustManager(InsecureTrustManagerFactory.INSTANCE)
        .build();
    
    // This would typically be used with a Netty HTTP client:
    // HttpClient client = HttpClient.create().secure(spec -> spec.sslContext(sslContext));
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1() throws Exception {
    // Using javax.net.ssl with proper certificate validation (default behavior)
    URL url = new URL("https://example.com");
    // ok: java-lack-of-tls-cert-verification
    HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
    connection.connect();
    // Default behavior validates certificates against the system's trust store
}

public void good_case_2() throws Exception {
    // Using Apache HttpClient with default certificate validation
    // ok: java-lack-of-tls-cert-verification
    HttpClient client = HttpClients.createDefault();
    
    HttpGet request = new HttpGet("https://example.com");
    client.execute(request);
    // Default HttpClient validates certificates against the system's trust store
}

public void good_case_3() throws Exception {
    // Using OkHttp3 with default certificate validation
    // ok: java-lack-of-tls-cert-verification
    OkHttpClient client = new OkHttpClient.Builder().build();
    
    Request request = new Request.Builder()
        .url("https://example.com")
        .build();
    
    Response response = client.newCall(request).execute();
    // Default OkHttpClient validates certificates against the system's trust store
}

public void good_case_4() throws Exception {
    // Using Spring RestTemplate with default certificate validation
    // ok: java-lack-of-tls-cert-verification
    RestTemplate restTemplate = new RestTemplate();
    
    restTemplate.getForObject("https://example.com", String.class);
    // Default RestTemplate validates certificates against the system's trust store
}

public void good_case_5() throws Exception {
    // Using Jetty HttpClient with default certificate validation
    SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
    
    // ok: java-lack-of-tls-cert-verification
    sslContextFactory.setTrustAll(false); // This is actually the default
    
    org.eclipse.jetty.client.HttpClient client = new org.eclipse.jetty.client.HttpClient(sslContextFactory);
    client.start();
    
    client.newRequest("https://example.com")
        .send();
}

public void good_case_6() throws Exception {
    // Using Retrofit with OkHttp and default certificate validation
    // ok: java-lack-of-tls-cert-verification
    OkHttpClient client = new OkHttpClient.Builder().build();
    
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl("https://example.com/")
        .client(client)
        .addConverterFactory(GsonConverterFactory.create())
        .build();
    // Default OkHttpClient validates certificates against the system's trust store
}

public void good_case_7() throws Exception {
    // Using AWS SDK with default certificate validation
    // ok: java-lack-of-tls-cert-verification
    ClientConfiguration clientConfig = new ClientConfiguration();
    // No custom SSL context set, uses the default which validates certificates
    
    AmazonS3Client s3Client = new AmazonS3Client(clientConfig);
    s3Client.listBuckets();
}

public void good_case_8() throws Exception {
    // Using Google API Client with default certificate validation
    // ok: java-lack-of-tls-cert-verification
    NetHttpTransport transport = GoogleNetHttpTransport.newTrustedTransport();
    
    // Use the transport for API calls
    // This would typically be used with a service like:
    // new Drive.Builder(transport, jsonFactory, credential).build();
}

public void good_case_9() throws Exception {
    // Using AsyncHttpClient with default certificate validation
    // ok: java-lack-of-tls-cert-verification
    DefaultAsyncHttpClientConfig.Builder configBuilder = new DefaultAsyncHttpClientConfig.Builder();
    // Not setting useInsecureTrustManager, which defaults to false
    
    AsyncHttpClient client = new DefaultAsyncHttpClient(configBuilder.build());
    client.prepareGet("https://example.com").execute();
}

public void good_case_10() throws Exception {
    // Using Jersey Client with default certificate validation
    // ok: java-lack-of-tls-cert-verification
    javax.ws.rs.client.Client client = JerseyClientBuilder.newClient();
    
    client.target("https://example.com").request().get();
    // Default Jersey Client validates certificates against the system's trust store
}

public void good_case_11() throws Exception {
    // Using Azure SDK with default certificate validation
    // ok: java-lack-of-tls-cert-verification
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .endpoint("https://example.blob.core.windows.net/")
        .buildClient();
    // Default Azure SDK client validates certificates against the system's trust store
}

public void good_case_12() throws Exception {
    // Using Vert.x HTTP client with default certificate validation
    Vertx vertx = Vertx.vertx();
    
    // ok: java-lack-of-tls-cert-verification
    HttpClientOptions options = new HttpClientOptions()
        .setSsl(true)
        .setTrustAll(false) // This is actually the default
        .setVerifyHost(true); // This is actually the default
    
    io.vertx.core.http.HttpClient client = vertx.createHttpClient(options);
    client.getNow(443, "example.com", "/", response -> {
        System.out.println("Received response with status code " + response.statusCode());
    });
}

public void good_case_13() throws Exception {
    // Using Ning AsyncHttpClient with default certificate validation
    com.ning.http.client.AsyncHttpClientConfig.Builder configBuilder = new com.ning.http.client.AsyncHttpClientConfig.Builder();
    
    // ok: java-lack-of-tls-cert-verification
    configBuilder.setAcceptAnyCertificate(false); // This is actually the default
    
    com.ning.http.client.AsyncHttpClient client = new com.ning.http.client.AsyncHttpClient(configBuilder.build());
    client.prepareGet("https://example.com").execute();
}

public void good_case_14() throws Exception {
    // Using AWS SDK v2 with default certificate validation
    // ok: java-lack-of-tls-cert-verification
    SdkHttpClient httpClient = ApacheHttpClient.builder().build();
    
    S3Client s3 = S3Client.builder()
        .httpClient(httpClient)
        .build();
    // Default AWS SDK v2 client validates certificates against the system's trust store
}

public void good_case_15() throws Exception {
    // Using Netty SslContext with default certificate validation
    // ok: java-lack-of-tls-cert-verification
    SslContext sslContext = SslContextBuilder.forClient()
        .build();
    
    // This would typically be used with a Netty HTTP client:
    // HttpClient client = HttpClient.create().secure(spec -> spec.sslContext(sslContext));
    // Default SslContext validates certificates against the system's trust store
}