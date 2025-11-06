import javax.net.ssl.*;
import java.io.IOException;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import okhttp3.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.client.RestTemplate;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import com.squareup.okhttp.OkHttpClient;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClientConfig;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.AsyncHttpClientConfig;

// Security Issue: Empty implementations of X509TrustManager that accept any certificate, making applications vulnerable to Man-in-the-Middle attacks

// True Positive Examples (Vulnerable/Insecure Code)

public class InsecureTrustManagerExamples {

    // Example 1: Basic Java HttpsURLConnection with insecure trust manager
// {fact rule=improper-certificate-validation@v1.0 defects=1}
    public static void bad_case_1() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // Do nothing -> accept any client
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Do nothing -> accept any server
                    }
                }
            };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Make an HTTPS request
            URL url = new URL("https://example.com/api/data");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 2: OkHttp3 client with insecure trust manager
    public static void bad_case_2() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        // Empty implementation
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        // Empty implementation
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0])
                .hostnameVerifier((hostname, session) -> true)
                .build();

            Request request = new Request.Builder()
                .url("https://example.com/api/data")
                .build();

            client.newCall(request).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 3: Apache HttpClient with insecure trust manager
    public static void bad_case_3() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                sslContext,
                new String[] { "TLSv1.2" },
                null,
                SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

            CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslsf)
                .build();

            HttpGet request = new HttpGet("https://example.com/api/data");
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 4: Spring RestTemplate with insecure trust manager
    public static void bad_case_4() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            
            org.apache.http.conn.ssl.SSLConnectionSocketFactory csf = new org.apache.http.conn.ssl.SSLConnectionSocketFactory(
                sslContext, 
                org.apache.http.conn.ssl.SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
            
            org.apache.http.impl.client.CloseableHttpClient httpClient = org.apache.http.impl.client.HttpClients.custom()
                .setSSLSocketFactory(csf)
                .build();
            
            org.springframework.http.client.HttpComponentsClientHttpRequestFactory requestFactory = 
                new org.springframework.http.client.HttpComponentsClientHttpRequestFactory();
            requestFactory.setHttpClient(httpClient);
            
            RestTemplate restTemplate = new RestTemplate(requestFactory);
            restTemplate.getForObject("https://example.com/api/data", String.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 5: Apache Commons HttpClient with insecure trust manager
    public static void bad_case_5() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            Protocol.registerProtocol("https", new Protocol("https", 
                (ProtocolSocketFactory) new org.apache.commons.httpclient.protocol.SSLProtocolSocketFactory(sslContext), 443));
            
            HttpClient client = new HttpClient();
            GetMethod method = new GetMethod("https://example.com/api/data");
            client.executeMethod(method);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 6: Retrofit with insecure trust manager
    public static void bad_case_6() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        // Empty implementation
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        // Empty implementation
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0])
                .hostnameVerifier((hostname, session) -> true)
                .build();

            Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://example.com/")
                .client(okHttpClient)
                .addConverterFactory(GsonConverterFactory.create())
                .build();
            
            // Use retrofit to make API calls
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 7: AWS SDK with insecure trust manager
    public static void bad_case_7() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // Create a custom HTTPS connection factory with our all-trusting manager
            javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            
            // Create an S3 client with a custom endpoint that might use HTTPS
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withEndpointConfiguration(
                    new AwsClientBuilder.EndpointConfiguration("https://custom-s3-endpoint.com", "us-west-2"))
                .withPathStyleAccessEnabled(true)
                .build();
            
            // Use the S3 client to make requests
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 8: Google HTTP Client with insecure trust manager
    public static void bad_case_8() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // Create a custom HTTP transport that uses our insecure SSL context
            NetHttpTransport.Builder builder = new NetHttpTransport.Builder();
            builder.doNotValidateCertificate();
            NetHttpTransport transport = builder.build();
            
            // Use the transport to make HTTP requests
            com.google.api.client.http.HttpRequestFactory requestFactory = transport.createRequestFactory();
            com.google.api.client.http.HttpRequest request = requestFactory.buildGetRequest(
                new com.google.api.client.http.GenericUrl("https://example.com/api/data"));
            request.execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 9: Azure SDK with insecure trust manager
    public static void bad_case_9() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // Create an Azure HTTP client with custom SSL context
            HttpClient httpClient = new NettyAsyncHttpClientBuilder()
                .sslContext(sslContext)
                .build();
            
            // Use the HTTP client with Azure services
            // For example, with Azure Storage:
            com.azure.storage.blob.BlobServiceClient blobServiceClient = new com.azure.storage.blob.BlobServiceClientBuilder()
                .endpoint("https://example.blob.core.windows.net/")
                .httpClient(httpClient)
                .buildClient();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 10: Apache HttpClient 5 with insecure trust manager
    public static void bad_case_10() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // Create an Apache HttpClient 5 with custom SSL context
            org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory sslSocketFactory = 
                SSLConnectionSocketFactoryBuilder.create()
                    .setSslContext(sslContext)
                    .setHostnameVerifier((hostname, session) -> true)
                    .build();
            
            org.apache.hc.client5.http.impl.classic.CloseableHttpClient httpClient = 
                org.apache.hc.client5.http.impl.classic.HttpClients.custom()
                    .setConnectionManager(
                        PoolingHttpClientConnectionManagerBuilder.create()
                            .setSSLSocketFactory(sslSocketFactory)
                            .build()
                    )
                    .build();
            
            // Use the client to make a request
            org.apache.hc.client5.http.classic.methods.HttpGet request = 
                new org.apache.hc.client5.http.classic.methods.HttpGet("https://example.com/api/data");
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 11: Jetty HttpClient with insecure trust manager
    public static void bad_case_11() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // Create a Jetty HTTP client with custom SSL context
            SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
            sslContextFactory.setSslContext(sslContext);
            sslContextFactory.setTrustAll(true);
            
            org.eclipse.jetty.client.HttpClient httpClient = new org.eclipse.jetty.client.HttpClient(sslContextFactory);
            httpClient.start();
            
            // Use the client to make a request
            org.eclipse.jetty.client.api.ContentResponse response = httpClient.GET("https://example.com/api/data");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 12: AWS SDK v2 with insecure trust manager
    public static void bad_case_12() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // Create an AWS SDK v2 HTTP client with custom SSL context
            SdkHttpClient httpClient = ApacheHttpClient.builder()
                .buildWithDefaults(
                    software.amazon.awssdk.http.apache.ProxyConfiguration.builder().build()
                );
            
            // Use the HTTP client with AWS services
            software.amazon.awssdk.services.s3.S3Client s3 = software.amazon.awssdk.services.s3.S3Client.builder()
                .httpClient(httpClient)
                .build();
            
            // Make a request
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 13: Old OkHttp client with insecure trust manager
    public static void bad_case_13() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // Create an old OkHttp client with custom SSL context
            com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
            client.setSslSocketFactory(sslContext.getSocketFactory());
            client.setHostnameVerifier((hostname, session) -> true);
            
            // Make a request
            com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder()
                .url("https://example.com/api/data")
                .build();
            
            client.newCall(request).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 14: AsyncHttpClient with insecure trust manager
    public static void bad_case_14() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // Create an AsyncHttpClient with custom SSL context
            DefaultAsyncHttpClientConfig.Builder configBuilder = new DefaultAsyncHttpClientConfig.Builder()
                .setSSLContext(sslContext)
                .setAcceptAnyCertificate(true);
            
            AsyncHttpClient client = new DefaultAsyncHttpClient(configBuilder.build());
            
            // Make a request
            client.prepareGet("https://example.com/api/data").execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 15: Ning AsyncHttpClient with insecure trust manager
    public static void bad_case_15() {
        try {
            // Create a trust manager that does not validate certificate chains
            // ruleid: java-insecure-trust-manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // No validation
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // Create a Ning AsyncHttpClient with custom SSL context
            AsyncHttpClientConfig config = new AsyncHttpClientConfig.Builder()
                .setSSLContext(sslContext)
                .setAcceptAnyCertificate(true)
                .build();
            
            com.ning.http.client.AsyncHttpClient client = new com.ning.http.client.AsyncHttpClient(config);
            
            // Make a request
            client.prepareGet("https://example.com/api/data").execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Example 1: Java HttpsURLConnection with proper certificate validation
    public static void good_case_1() {
        try {
            // Use the default trust manager which validates certificates
            // ok: java-insecure-trust-manager
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null); // You can load your own keystore here
            tmf.init(ks);
            
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, tmf.getTrustManagers(), new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
            // Make an HTTPS request
            URL url = new URL("https://example.com/api/data");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 2: OkHttp3 client with proper certificate validation
    public static void good_case_2() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            
            OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(sslSocketFactory, (X509TrustManager) trustManagers[0])
                .build();
            
            Request request = new Request.Builder()
                .url("https://example.com/api/data")
                .build();
            
            client.newCall(request).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 3: Apache HttpClient with proper certificate validation
    public static void good_case_3() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                sslContext,
                new String[] { "TLSv1.2" },
                null,
                SSLConnectionSocketFactory.getDefaultHostnameVerifier());
            
            CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslsf)
                .build();
            
            HttpGet request = new HttpGet("https://example.com/api/data");
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 4: Spring RestTemplate with proper certificate validation
    public static void good_case_4() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            
            org.apache.http.conn.ssl.SSLConnectionSocketFactory csf = new org.apache.http.conn.ssl.SSLConnectionSocketFactory(
                sslContext, 
                org.apache.http.conn.ssl.SSLConnectionSocketFactory.getDefaultHostnameVerifier());
            
            org.apache.http.impl.client.CloseableHttpClient httpClient = org.apache.http.impl.client.HttpClients.custom()
                .setSSLSocketFactory(csf)
                .build();
            
            org.springframework.http.client.HttpComponentsClientHttpRequestFactory requestFactory = 
                new org.springframework.http.client.HttpComponentsClientHttpRequestFactory();
            requestFactory.setHttpClient(httpClient);
            
            RestTemplate restTemplate = new RestTemplate(requestFactory);
            restTemplate.getForObject("https://example.com/api/data", String.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 5: Apache Commons HttpClient with proper certificate validation
    public static void good_case_5() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            
            Protocol.registerProtocol("https", new Protocol("https", 
                (ProtocolSocketFactory) new org.apache.commons.httpclient.protocol.SSLProtocolSocketFactory(sslContext), 443));
            
            HttpClient client = new HttpClient();
            GetMethod method = new GetMethod("https://example.com/api/data");
            client.executeMethod(method);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 6: Retrofit with proper certificate validation
    public static void good_case_6() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            
            OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .sslSocketFactory(sslSocketFactory, (X509TrustManager) trustManagerFactory.getTrustManagers()[0])
                .build();
            
            Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://example.com/")
                .client(okHttpClient)
                .addConverterFactory(GsonConverterFactory.create())
                .build();
            
            // Use retrofit to make API calls
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 7: AWS SDK with proper certificate validation
    public static void good_case_7() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);
            trustManagerFactory.init(keyStore);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            
            // Create an S3 client with proper certificate validation
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withEndpointConfiguration(
                    new AwsClientBuilder.EndpointConfiguration("https://custom-s3-endpoint.com", "us-west-2"))
                .withPathStyleAccessEnabled(true)
                .build();
            
            // Use the S3 client to make requests
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 8: Google HTTP Client with proper certificate validation
    public static void good_case_8() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            
            // Create a custom HTTP transport that uses proper SSL context
            NetHttpTransport transport = new NetHttpTransport.Builder()
                .setSslSocketFactory(sslContext.getSocketFactory())
                .build();
            
            // Use the transport to make HTTP requests
            com.google.api.client.http.HttpRequestFactory requestFactory = transport.createRequestFactory();
            com.google.api.client.http.HttpRequest request = requestFactory.buildGetRequest(
                new com.google.api.client.http.GenericUrl("https://example.com/api/data"));
            request.execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 9: Azure SDK with proper certificate validation
    public static void good_case_9() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            
            // Create an Azure HTTP client with proper SSL context
            HttpClient httpClient = new NettyAsyncHttpClientBuilder()
                .sslContext(sslContext)
                .build();
            
            // Use the HTTP client with Azure services
            // For example, with Azure Storage:
            com.azure.storage.blob.BlobServiceClient blobServiceClient = new com.azure.storage.blob.BlobServiceClientBuilder()
                .endpoint("https://example.blob.core.windows.net/")
                .httpClient(httpClient)
                .buildClient();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 10: Apache HttpClient 5 with proper certificate validation
    public static void good_case_10() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            
            // Create an Apache HttpClient 5 with proper SSL context
            org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory sslSocketFactory = 
                SSLConnectionSocketFactoryBuilder.create()
                    .setSslContext(sslContext)
                    .build();
            
            org.apache.hc.client5.http.impl.classic.CloseableHttpClient httpClient = 
                org.apache.hc.client5.http.impl.classic.HttpClients.custom()
                    .setConnectionManager(
                        PoolingHttpClientConnectionManagerBuilder.create()
                            .setSSLSocketFactory(sslSocketFactory)
                            .build()
                    )
                    .build();
            
            // Use the client to make a request
            org.apache.hc.client5.http.classic.methods.HttpGet request = 
                new org.apache.hc.client5.http.classic.methods.HttpGet("https://example.com/api/data");
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 11: Jetty HttpClient with proper certificate validation
    public static void good_case_11() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            
            // Create a Jetty HTTP client with proper SSL context
            SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
            sslContextFactory.setSslContext(sslContext);
            
            org.eclipse.jetty.client.HttpClient httpClient = new org.eclipse.jetty.client.HttpClient(sslContextFactory);
            httpClient.start();
            
            // Use the client to make a request
            org.eclipse.jetty.client.api.ContentResponse response = httpClient.GET("https://example.com/api/data");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 12: AWS SDK v2 with proper certificate validation
    public static void good_case_12() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            
            // Create an AWS SDK v2 HTTP client with proper certificate validation
            SdkHttpClient httpClient = UrlConnectionHttpClient.builder().build();
            
            // Use the HTTP client with AWS services
            software.amazon.awssdk.services.s3.S3Client s3 = software.amazon.awssdk.services.s3.S3Client.builder()
                .httpClient(httpClient)
                .build();
            
            // Make a request
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 13: Old OkHttp client with proper certificate validation
    public static void good_case_13() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            
            // Create an old OkHttp client with proper SSL context
            com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
            client.setSslSocketFactory(sslContext.getSocketFactory());
            
            // Make a request
            com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder()
                .url("https://example.com/api/data")
                .build();
            
            client.newCall(request).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 14: AsyncHttpClient with proper certificate validation
    public static void good_case_14() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            
            // Create an AsyncHttpClient with proper SSL context
            DefaultAsyncHttpClientConfig.Builder configBuilder = new DefaultAsyncHttpClientConfig.Builder()
                .setSSLContext(sslContext);
            
            AsyncHttpClient client = new DefaultAsyncHttpClient(configBuilder.build());
            
            // Make a request
            client.prepareGet("https://example.com/api/data").execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Example 15: Ning AsyncHttpClient with proper certificate validation
    public static void good_case_15() {
        try {
            // ok: java-insecure-trust-manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            
            // Create a Ning AsyncHttpClient with proper SSL context
            AsyncHttpClientConfig config = new AsyncHttpClientConfig.Builder()
                .setSSLContext(sslContext)
                .build();
            
            com.ning.http.client.AsyncHttpClient client = new com.ning.http.client.AsyncHttpClient(config);
            
            // Make a request
            client.prepareGet("https://example.com/api/data").execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}