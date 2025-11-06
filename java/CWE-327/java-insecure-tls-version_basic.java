import java.net.URL;
import java.net.HttpURLConnection;
import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.util.Arrays;
import java.util.Properties;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.client.methods.HttpGet;
import javax.mail.Session;
import javax.mail.Transport;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.catalina.connector.Connector;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class InsecureTLSExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public void bad_case_1() throws NoSuchAlgorithmException, KeyManagementException {
        // ruleid: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, null, new SecureRandom());
        SSLContext.setDefault(sslContext);
    }
    
    public void bad_case_2() throws NoSuchAlgorithmException, KeyManagementException {
        // ruleid: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("SSLv3");
        sslContext.init(null, null, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    }
    
    public void bad_case_3() throws NoSuchAlgorithmException, KeyManagementException {
        // ruleid: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1.1");
        sslContext.init(null, null, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    }
    
    public void bad_case_4() throws Exception {
        // ruleid: java-insecure-tls-version
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            SSLContexts.custom().build(),
            new String[] { "TLSv1" },
            null,
            SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        
        HttpClient httpClient = HttpClients.custom()
            .setSSLSocketFactory(sslsf)
            .build();
    }
    
    public void bad_case_5() throws Exception {
        // ruleid: java-insecure-tls-version
        SSLContextBuilder builder = SSLContexts.custom();
        SSLContext sslContext = builder.build();
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            sslContext,
            new String[] { "SSLv3", "TLSv1" },
            null,
            SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        
        HttpClient httpClient = HttpClients.custom()
            .setSSLSocketFactory(sslsf)
            .build();
    }
    
    public void bad_case_6() {
        // ruleid: java-insecure-tls-version
        System.setProperty("https.protocols", "TLSv1");
        try {
            URL url = new URL("https://example.com");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_7() {
        // ruleid: java-insecure-tls-version
        System.setProperty("jdk.tls.client.protocols", "TLSv1.1,TLSv1");
        try {
            URL url = new URL("https://example.com");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_8() throws Exception {
        // ruleid: java-insecure-tls-version
        Properties props = new Properties();
        props.put("mail.smtp.ssl.protocols", "SSLv3");
        props.put("mail.smtp.host", "smtp.example.com");
        props.put("mail.smtp.port", "465");
        props.put("mail.smtp.ssl.enable", "true");
        
        Session session = Session.getInstance(props);
        Transport transport = session.getTransport("smtp");
    }
    
    public void bad_case_9() throws Exception {
        // ruleid: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, new TrustManager[]{new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }}, new SecureRandom());
        
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    }
    
    public void bad_case_10() throws Exception {
        // ruleid: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1.1");
        sslContext.init(null, null, new SecureRandom());
        
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
        SSLConnectionSocketFactory sslConnectionFactory = new SSLConnectionSocketFactory(sslContext);
        HttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslConnectionFactory).build();
        factory.setHttpClient(httpClient);
        
        RestTemplate restTemplate = new RestTemplate(factory);
    }
    
    public void bad_case_11() {
        WebServerFactoryCustomizer<TomcatServletWebServerFactory> tomcatCustomizer = new WebServerFactoryCustomizer<TomcatServletWebServerFactory>() {
            @Override
            public void customize(TomcatServletWebServerFactory factory) {
                factory.addConnectorCustomizers(connector -> {
                    // ruleid: java-insecure-tls-version
                    connector.addSslHostConfig(new SSLHostConfig() {{
                        setProtocols("TLSv1");
                    }});
                });
            }
        };
    }
    
    public void bad_case_12() throws Exception {
        // ruleid: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("SSLv3");
        sslContext.init(null, null, new SecureRandom());
        
        SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(8443);
    }
    
    public void bad_case_13() throws Exception {
        // ruleid: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, null, new SecureRandom());
        
        SSLSocketFactory sf = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) sf.createSocket("example.com", 443);
        socket.setEnabledProtocols(new String[] {"TLSv1"});
    }
    
    public void bad_case_14() throws Exception {
        // ruleid: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, null, new SecureRandom());
        
        SSLEngine engine = sslContext.createSSLEngine();
        engine.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1"});
    }
    
    public void bad_case_15() {
        Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setScheme("https");
        connector.setSecure(true);
        connector.setPort(8443);
        
        // ruleid: java-insecure-tls-version
        connector.setAttribute("sslProtocols", "TLSv1");
    }
    
    // True Negative Examples (Secure Code)
    
    public void good_case_1() throws NoSuchAlgorithmException, KeyManagementException {
        // ok: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        SSLContext.setDefault(sslContext);
    }
    
    public void good_case_2() throws NoSuchAlgorithmException, KeyManagementException {
        // ok: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, null, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    }
    
    public void good_case_3() throws Exception {
        // ok: java-insecure-tls-version
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            SSLContexts.custom().build(),
            new String[] { "TLSv1.2", "TLSv1.3" },
            null,
            SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        
        HttpClient httpClient = HttpClients.custom()
            .setSSLSocketFactory(sslsf)
            .build();
    }
    
    public void good_case_4() {
        // ok: java-insecure-tls-version
        System.setProperty("https.protocols", "TLSv1.2,TLSv1.3");
        try {
            URL url = new URL("https://example.com");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_5() {
        // ok: java-insecure-tls-version
        System.setProperty("jdk.tls.client.protocols", "TLSv1.2,TLSv1.3");
        try {
            URL url = new URL("https://example.com");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_6() throws Exception {
        // ok: java-insecure-tls-version
        Properties props = new Properties();
        props.put("mail.smtp.ssl.protocols", "TLSv1.2");
        props.put("mail.smtp.host", "smtp.example.com");
        props.put("mail.smtp.port", "465");
        props.put("mail.smtp.ssl.enable", "true");
        
        Session session = Session.getInstance(props);
        Transport transport = session.getTransport("smtp");
    }
    
    public void good_case_7() throws Exception {
        // ok: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, new TrustManager[]{new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }}, new SecureRandom());
        
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    }
    
    public void good_case_8() throws Exception {
        // ok: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, null, new SecureRandom());
        
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
        SSLConnectionSocketFactory sslConnectionFactory = new SSLConnectionSocketFactory(sslContext);
        HttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslConnectionFactory).build();
        factory.setHttpClient(httpClient);
        
        RestTemplate restTemplate = new RestTemplate(factory);
    }
    
    public void good_case_9() {
        WebServerFactoryCustomizer<TomcatServletWebServerFactory> tomcatCustomizer = new WebServerFactoryCustomizer<TomcatServletWebServerFactory>() {
            @Override
            public void customize(TomcatServletWebServerFactory factory) {
                factory.addConnectorCustomizers(connector -> {
                    // ok: java-insecure-tls-version
                    connector.addSslHostConfig(new SSLHostConfig() {{
                        setProtocols("TLSv1.2+TLSv1.3");
                    }});
                });
            }
        };
    }
    
    public void good_case_10() throws Exception {
        // ok: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(8443);
    }
    
    public void good_case_11() throws Exception {
        // ok: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLS"); // Default to highest available
        sslContext.init(null, null, new SecureRandom());
        
        SSLSocketFactory sf = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) sf.createSocket("example.com", 443);
        socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
    }
    
    public void good_case_12() throws Exception {
        // ok: java-insecure-tls-version
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        SSLEngine engine = sslContext.createSSLEngine();
        engine.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
    }
    
    public void good_case_13() {
        Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setScheme("https");
        connector.setSecure(true);
        connector.setPort(8443);
        
        // ok: java-insecure-tls-version
        connector.setAttribute("sslProtocols", "TLSv1.2,TLSv1.3");
    }
    
    public void good_case_14() throws Exception {
        // ok: java-insecure-tls-version
        SSLContext context = SSLContext.getDefault(); // Uses system default which is typically secure
        HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
    }
    
    public void good_case_15() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = new FileInputStream("keystore.jks")) {
            keyStore.load(in, "password".toCharArray());
        }
        
        // ok: java-insecure-tls-version
        SSLContext sslContext = SSLContexts.custom()
            .loadKeyMaterial(keyStore, "password".toCharArray())
            .build();
        
        // No explicit protocol version specified, defaults to secure TLS
    }
    
    // Helper class for trust manager
    private static class X509TrustManager implements javax.net.ssl.X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
// {/fact}