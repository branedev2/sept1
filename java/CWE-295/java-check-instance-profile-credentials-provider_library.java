import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.io.IOException;
import java.net.URL;
import java.net.HttpURLConnection;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.ssl.SSLContextBuilder;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;

import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;

import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.asynchttpclient.AsyncHttpClientConfig;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.net.JksOptions;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;

import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import com.google.cloud.http.HttpTransportOptions;
import com.google.cloud.storage.StorageOptions;

import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;

// Security Issue: Insecure Trust Manager accepts any certificate, enabling Man-in-the-Middle attacks

// True Positive Examples (Vulnerable/Insecure Code)
public void bad_case_1() {
    try {
        // Create a trust manager that does not validate certificate chains
        // ruleid: java-check-instance-profile-credentials-provider
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }
        };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        
        // Make an HTTPS request
        URL url = new URL("https://example.com/api");
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.connect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    try {
        // Using Apache HttpClient with insecure trust manager
        // ruleid: java-check-instance-profile-credentials-provider
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        }, null);
        
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext);
        HttpClient client = HttpClients.custom().setSSLSocketFactory(sslsf).build();
        
        // Use the client to make requests
        org.apache.http.client.methods.HttpGet request = 
            new org.apache.http.client.methods.HttpGet("https://example.com/api");
        client.execute(request);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    try {
        // OkHttp3 with insecure trust manager
        // ruleid: java-check-instance-profile-credentials-provider
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) { }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) { }

                @Override
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        
        OkHttpClient client = new OkHttpClient.Builder()
            .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0])
            .hostnameVerifier((hostname, session) -> true)
            .build();
        
        Request request = new Request.Builder()
            .url("https://example.com/api")
            .build();
        
        Response response = client.newCall(request).execute();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4() {
    try {
        // AWS SDK with insecure SSL configuration
        // ruleid: java-check-instance-profile-credentials-provider
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };
        
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        
        ClientConfiguration clientConfig = new ClientConfiguration();
        clientConfig.getApacheHttpClientConfig().setSslSocketFactory(
            new org.apache.http.conn.ssl.SSLSocketFactory(sc));
        
        AWSCredentials credentials = new BasicAWSCredentials("access_key", "secret_key");
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
            .withCredentials(new AWSStaticCredentialsProvider(credentials))
            .withClientConfiguration(clientConfig)
            .withRegion("us-west-2")
            .build();
        
        s3Client.listBuckets();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    try {
        // Spring RestTemplate with insecure trust manager
        // ruleid: java-check-instance-profile-credentials-provider
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        
        org.apache.http.conn.ssl.SSLConnectionSocketFactory csf = 
            new org.apache.http.conn.ssl.SSLConnectionSocketFactory(sslContext);
        
        org.apache.http.impl.client.CloseableHttpClient httpClient = 
            org.apache.http.impl.client.HttpClients.custom().setSSLSocketFactory(csf).build();
        
        HttpComponentsClientHttpRequestFactory requestFactory = 
            new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(httpClient);
        
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        restTemplate.getForObject("https://example.com/api", String.class);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    try {
        // Google HTTP Client with insecure trust manager
        // ruleid: java-check-instance-profile-credentials-provider
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        
        NetHttpTransport.Builder builder = new NetHttpTransport.Builder();
        builder.doNotValidateCertificate();
        HttpTransport httpTransport = builder.build();
        
        com.google.api.client.http.HttpRequest request = 
            httpTransport.createRequestFactory()
                .buildGetRequest(new com.google.api.client.http.GenericUrl("https://example.com/api"));
        request.execute();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    try {
        // Retrofit with insecure OkHttp client
        // ruleid: java-check-instance-profile-credentials-provider
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
            .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0])
            .hostnameVerifier((hostname, session) -> true)
            .build();
        
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://example.com/")
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    try {
        // AsyncHttpClient with insecure SSL configuration
        // ruleid: java-check-instance-profile-credentials-provider
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        
        AsyncHttpClientConfig config = new AsyncHttpClientConfig.Builder()
            .setSSLContext(sslContext)
            .setAcceptAnyCertificate(true)
            .build();
        
        AsyncHttpClient client = new DefaultAsyncHttpClient(config);
        client.prepareGet("https://example.com/api").execute();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    // Vert.x HTTP client with insecure SSL options
    // ruleid: java-check-instance-profile-credentials-provider
    Vertx vertx = Vertx.vertx();
    HttpClientOptions options = new HttpClientOptions()
        .setSsl(true)
        .setTrustAll(true)  // This is insecure
        .setVerifyHost(false);
    
    io.vertx.core.http.HttpClient client = vertx.createHttpClient(options);
    client.getNow(443, "example.com", "/api", response -> {
        System.out.println("Received response with status code " + response.statusCode());
    });
}

public void bad_case_10() {
    try {
        // Netty with insecure trust manager
        // ruleid: java-check-instance-profile-credentials-provider
        SslContext sslContext = SslContextBuilder.forClient()
            .trustManager(InsecureTrustManagerFactory.INSTANCE)
            .build();
        
        io.netty.bootstrap.Bootstrap bootstrap = new io.netty.bootstrap.Bootstrap();
        // Configure bootstrap with the insecure SSL context
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    // Azure SDK with insecure HTTP client
    try {
        // ruleid: java-check-instance-profile-credentials-provider
        HttpClient httpClient = new NettyAsyncHttpClientBuilder()
            .disableCertificateValidation()
            .build();
        
        // Use the HTTP client with Azure services
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    try {
        // OkHttp (Square version) with insecure trust manager
        // ruleid: java-check-instance-profile-credentials-provider
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        
        com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
        client.setSslSocketFactory(sslContext.getSocketFactory());
        client.setHostnameVerifier((hostname, session) -> true);
        
        com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder()
            .url("https://example.com/api")
            .build();
        
        client.newCall(request).execute();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13() {
    try {
        // Jetty HTTP client with insecure SSL configuration
        // ruleid: java-check-instance-profile-credentials-provider
        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setTrustAll(true);
        
        org.eclipse.jetty.client.HttpClient client = new org.eclipse.jetty.client.HttpClient(sslContextFactory);
        client.start();
        
        org.eclipse.jetty.client.api.ContentResponse response = client.GET("https://example.com/api");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    // Google Cloud Storage with insecure HTTP transport
    try {
        // ruleid: java-check-instance-profile-credentials-provider
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        
        HttpTransportOptions transportOptions = HttpTransportOptions.newBuilder()
            .setHttpTransportFactory(() -> {
                try {
                    return new NetHttpTransport.Builder()
                        .doNotValidateCertificate()
                        .build();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            })
            .build();
        
        StorageOptions options = StorageOptions.newBuilder()
            .setTransportOptions(transportOptions)
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15() {
    // AWS SDK v2 with insecure HTTP client
    try {
        // ruleid: java-check-instance-profile-credentials-provider
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        
        SdkHttpClient httpClient = ApacheHttpClient.builder()
            .tlsKeyManagersProvider(() -> null)
            .tlsTrustManagersProvider(() -> trustAllCerts)
            .build();
        
        // Use the HTTP client with AWS SDK v2 services
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)
public void good_case_1() {
    try {
        // Using default HttpsURLConnection which validates certificates
        // ok: java-check-instance-profile-credentials-provider
        URL url = new URL("https://example.com/api");
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.connect();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    try {
        // Apache HttpClient with proper certificate validation
        // ok: java-check-instance-profile-credentials-provider
        SSLContext sslContext = SSLContextBuilder.create()
            .loadTrustMaterial(null, new TrustSelfSignedStrategy())
            .build();
        
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            sslContext, new String[] { "TLSv1.2" }, null, 
            SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        
        HttpClient client = HttpClients.custom()
            .setSSLSocketFactory(sslsf)
            .build();
        
        // Use the client to make requests
        org.apache.http.client.methods.HttpGet request = 
            new org.apache.http.client.methods.HttpGet("https://example.com/api");
        client.execute(request);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    try {
        // OkHttp3 with proper certificate validation (default behavior)
        // ok: java-check-instance-profile-credentials-provider
        OkHttpClient client = new OkHttpClient.Builder()
            .build();  // Default configuration validates certificates
        
        Request request = new Request.Builder()
            .url("https://example.com/api")
            .build();
        
        Response response = client.newCall(request).execute();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4() {
    try {
        // AWS SDK with proper SSL configuration (default behavior)
        // ok: java-check-instance-profile-credentials-provider
        AWSCredentials credentials = new BasicAWSCredentials("access_key", "secret_key");
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
            .withCredentials(new AWSStaticCredentialsProvider(credentials))
            .withRegion("us-west-2")
            .build();  // Default configuration validates certificates
        
        s3Client.listBuckets();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    try {
        // Spring RestTemplate with proper certificate validation (default behavior)
        // ok: java-check-instance-profile-credentials-provider
        RestTemplate restTemplate = new RestTemplate();
        String response = restTemplate.getForObject("https://example.com/api", String.class);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    try {
        // Google HTTP Client with proper certificate validation
        // ok: java-check-instance-profile-credentials-provider
        HttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        
        com.google.api.client.http.HttpRequest request = 
            httpTransport.createRequestFactory()
                .buildGetRequest(new com.google.api.client.http.GenericUrl("https://example.com/api"));
        request.execute();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    try {
        // Retrofit with default OkHttp client (validates certificates)
        // ok: java-check-instance-profile-credentials-provider
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
            .build();  // Default configuration validates certificates
        
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://example.com/")
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    try {
        // AsyncHttpClient with proper SSL configuration (default behavior)
        // ok: java-check-instance-profile-credentials-provider
        AsyncHttpClient client = new DefaultAsyncHttpClient();
        client.prepareGet("https://example.com/api").execute();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    // Vert.x HTTP client with proper SSL options
    // ok: java-check-instance-profile-credentials-provider
    Vertx vertx = Vertx.vertx();
    HttpClientOptions options = new HttpClientOptions()
        .setSsl(true)
        .setTrustAll(false)  // Default is false, but being explicit
        .setVerifyHost(true);  // Default is true, but being explicit
    
    io.vertx.core.http.HttpClient client = vertx.createHttpClient(options);
    client.getNow(443, "example.com", "/api", response -> {
        System.out.println("Received response with status code " + response.statusCode());
    });
}

public void good_case_10() {
    try {
        // Netty with proper trust manager (using system default)
        // ok: java-check-instance-profile-credentials-provider
        SslContext sslContext = SslContextBuilder.forClient()
            .build();  // Uses system default trust manager
        
        io.netty.bootstrap.Bootstrap bootstrap = new io.netty.bootstrap.Bootstrap();
        // Configure bootstrap with the secure SSL context
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // Azure SDK with proper HTTP client (default behavior)
    // ok: java-check-instance-profile-credentials-provider
    HttpClient httpClient = new NettyAsyncHttpClientBuilder()
        .build();  // Default configuration validates certificates
    
    // Use the HTTP client with Azure services
}

public void good_case_12() {
    try {
        // OkHttp (Square version) with proper certificate validation (default behavior)
        // ok: java-check-instance-profile-credentials-provider
        com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
        // Default configuration validates certificates
        
        com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder()
            .url("https://example.com/api")
            .build();
        
        client.newCall(request).execute();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13() {
    try {
        // Jetty HTTP client with proper SSL configuration
        // ok: java-check-instance-profile-credentials-provider
        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setTrustAll(false);  // Default is false, but being explicit
        
        org.eclipse.jetty.client.HttpClient client = new org.eclipse.jetty.client.HttpClient(sslContextFactory);
        client.start();
        
        org.eclipse.jetty.client.api.ContentResponse response = client.GET("https://example.com/api");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14() {
    // Google Cloud Storage with proper HTTP transport (default behavior)
    // ok: java-check-instance-profile-credentials-provider
    StorageOptions options = StorageOptions.getDefaultInstance();
    // Default configuration validates certificates
}

public void good_case_15() {
    // AWS SDK v2 with proper HTTP client (default behavior)
    // ok: java-check-instance-profile-credentials-provider
    SdkHttpClient httpClient = UrlConnectionHttpClient.create();
    // Default configuration validates certificates
    
    // Use the HTTP client with AWS SDK v2 services
}