import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.net.ssl.*;
import java.net.HttpURLConnection;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.HttpResponse;
import okhttp3.OkHttpClient;
import okhttp3.ConnectionSpec;
import okhttp3.TlsVersion;
import okhttp3.CipherSuite;
import java.util.Collections;
import java.util.ArrayList;
import java.util.List;

public class CipherSuiteExamples {

    // True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public void bad_case_1() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        
        // Creating SSLSocketFactory with default cipher suites (missing recommended ones)
        // ruleid: java-missing-supported-cipher-suites
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        
        HttpsURLConnection connection = null;
        try {
            URL url = new URL("https://api.example.com");
            connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(socketFactory);
            connection.connect();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() throws NoSuchAlgorithmException, KeyManagementException {
        // Creating an empty array of cipher suites (none configured)
        String[] emptyCipherSuites = new String[0];
        
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, null);
        
        // ruleid: java-missing-supported-cipher-suites
        SSLSocketFactory socketFactory = new CustomSSLSocketFactory(sslContext.getSocketFactory(), emptyCipherSuites);
        
        try {
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(socketFactory);
            connection.connect();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() throws NoSuchAlgorithmException, KeyManagementException {
        // Using only old, weak cipher suites
        String[] weakCipherSuites = {
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA"
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        
        // ruleid: java-missing-supported-cipher-suites
        SSLSocketFactory socketFactory = new CustomSSLSocketFactory(sslContext.getSocketFactory(), weakCipherSuites);
        
        try {
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(socketFactory);
            connection.connect();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() throws NoSuchAlgorithmException, KeyManagementException {
        // Using Apache HttpClient with default cipher suites
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        
        // ruleid: java-missing-supported-cipher-suites
        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
            sslContext,
            null, // Use default supported protocols
            null, // Use default supported cipher suites
            SSLConnectionSocketFactory.getDefaultHostnameVerifier()
        );
        
        HttpClient httpClient = HttpClients.custom()
            .setSSLSocketFactory(sslSocketFactory)
            .build();
        
        try {
            HttpGet request = new HttpGet("https://api.example.com");
            HttpResponse response = httpClient.execute(request);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() throws NoSuchAlgorithmException, KeyManagementException {
        // Using OkHttp with insufficient cipher suites
        ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .tlsVersions(TlsVersion.TLS_1_2)
            .cipherSuites(
                // ruleid: java-missing-supported-cipher-suites
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
            )
            .build();
        
        OkHttpClient client = new OkHttpClient.Builder()
            .connectionSpecs(Collections.singletonList(spec))
            .build();
    }

    public void bad_case_6() {
        try {
            // Using SSLContext with TLSv1.0 (outdated)
            // ruleid: java-missing-supported-cipher-suites
            SSLContext sslContext = SSLContext.getInstance("TLSv1");
            sslContext.init(null, null, null);
            
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            // Using SSLContext with SSLv3 (very outdated and insecure)
            // ruleid: java-missing-supported-cipher-suites
            SSLContext sslContext = SSLContext.getInstance("SSLv3");
            sslContext.init(null, null, null);
            
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            // Using explicitly weak cipher suites with Apache HttpClient
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            
            String[] weakCipherSuites = {
                "SSL_RSA_WITH_RC4_128_SHA",
                "SSL_RSA_WITH_3DES_EDE_CBC_SHA"
            };
            
            // ruleid: java-missing-supported-cipher-suites
            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1", "TLSv1.1"}, // Outdated protocols
                weakCipherSuites,
                SSLConnectionSocketFactory.getDefaultHostnameVerifier()
            );
            
            HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslSocketFactory)
                .build();
            
            HttpGet request = new HttpGet("https://api.example.com");
            HttpResponse response = httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        // Using OkHttp with TLS 1.0 only (outdated)
        ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            // ruleid: java-missing-supported-cipher-suites
            .tlsVersions(TlsVersion.TLS_1_0)
            .cipherSuites(
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
            )
            .build();
        
        OkHttpClient client = new OkHttpClient.Builder()
            .connectionSpecs(Collections.singletonList(spec))
            .build();
    }

    public void bad_case_10() {
        try {
            // Creating a custom SSLSocketFactory with no explicit cipher suites
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            
            // ruleid: java-missing-supported-cipher-suites
            SSLSocketFactory factory = new SSLSocketFactory() {
                private final SSLSocketFactory delegate = sslContext.getSocketFactory();
                
                @Override
                public String[] getDefaultCipherSuites() {
                    return delegate.getDefaultCipherSuites();
                }
                
                @Override
                public String[] getSupportedCipherSuites() {
                    return delegate.getSupportedCipherSuites();
                }
                
                @Override
                public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
                    return delegate.createSocket(s, host, port, autoClose);
                }
                
                @Override
                public Socket createSocket(String host, int port) throws IOException {
                    return delegate.createSocket(host, port);
                }
                
                @Override
                public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
                    return delegate.createSocket(host, port, localHost, localPort);
                }
                
                @Override
                public Socket createSocket(InetAddress host, int port) throws IOException {
                    return delegate.createSocket(host, port);
                }
                
                @Override
                public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
                    return delegate.createSocket(address, port, localAddress, localPort);
                }
            };
            
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(factory);
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            // Using a mix of secure and insecure cipher suites, but missing recommended ones
            String[] mixedCipherSuites = {
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA" // Weak cipher
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            
            // ruleid: java-missing-supported-cipher-suites
            SSLSocketFactory socketFactory = new CustomSSLSocketFactory(sslContext.getSocketFactory(), mixedCipherSuites);
            
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(socketFactory);
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        // Using OkHttp with COMPATIBLE TLS (allows older protocols)
        // ruleid: java-missing-supported-cipher-suites
        ConnectionSpec spec = ConnectionSpec.COMPATIBLE_TLS;
        
        OkHttpClient client = new OkHttpClient.Builder()
            .connectionSpecs(Collections.singletonList(spec))
            .build();
    }

    public void bad_case_13() {
        try {
            // Using Apache HttpClient with explicitly limited protocols
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            
            // ruleid: java-missing-supported-cipher-suites
            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1.1"}, // Missing TLSv1.2 and TLSv1.3
                null, // Default cipher suites
                SSLConnectionSocketFactory.getDefaultHostnameVerifier()
            );
            
            HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslSocketFactory)
                .build();
            
            HttpGet request = new HttpGet("https://api.example.com");
            HttpResponse response = httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // Using system properties to set cipher suites with weak options
            System.setProperty("https.cipherSuites", 
                // ruleid: java-missing-supported-cipher-suites
                "TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA"
            );
            
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            // Using a custom TrustManager but with default cipher suites
            SSLContext sslContext = SSLContext.getInstance("TLS");
            
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
            };
            
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            
            // ruleid: java-missing-supported-cipher-suites
            SSLSocketFactory socketFactory = sslContext.getSocketFactory();
            
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(socketFactory);
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1() throws NoSuchAlgorithmException, KeyManagementException {
        // Using strong, recommended cipher suites
        String[] recommendedCipherSuites = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, null);
        
        // ok: java-missing-supported-cipher-suites
        SSLSocketFactory socketFactory = new CustomSSLSocketFactory(sslContext.getSocketFactory(), recommendedCipherSuites);
        
        try {
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(socketFactory);
            connection.connect();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() throws NoSuchAlgorithmException, KeyManagementException {
        // Using Apache HttpClient with strong cipher suites
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, null);
        
        String[] strongCipherSuites = {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        };
        
        // ok: java-missing-supported-cipher-suites
        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
            sslContext,
            new String[] {"TLSv1.2", "TLSv1.3"}, // Modern protocols
            strongCipherSuites,
            SSLConnectionSocketFactory.getDefaultHostnameVerifier()
        );
        
        HttpClient httpClient = HttpClients.custom()
            .setSSLSocketFactory(sslSocketFactory)
            .build();
        
        try {
            HttpGet request = new HttpGet("https://api.example.com");
            HttpResponse response = httpClient.execute(request);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        // Using OkHttp with strong cipher suites
        List<CipherSuite> strongCipherSuites = new ArrayList<>();
        strongCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        strongCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        strongCipherSuites.add(CipherSuite.TLS_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256);
        strongCipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        strongCipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        strongCipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        strongCipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        
        // ok: java-missing-supported-cipher-suites
        ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)
            .cipherSuites(strongCipherSuites.toArray(new CipherSuite[0]))
            .build();
        
        OkHttpClient client = new OkHttpClient.Builder()
            .connectionSpecs(Collections.singletonList(spec))
            .build();
    }

    public void good_case_4() {
        try {
            // Using system properties to set strong cipher suites
            // ok: java-missing-supported-cipher-suites
            System.setProperty("https.cipherSuites", 
                "TLS_AES_128_GCM_SHA256," +
                "TLS_AES_256_GCM_SHA384," +
                "TLS_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256," +
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256," +
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384," +
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256," +
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            );
            
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            // Using SSLContext with TLSv1.3 (latest)
            // ok: java-missing-supported-cipher-suites
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(null, null, null);
            
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        // Using OkHttp with MODERN_TLS specification
        // ok: java-missing-supported-cipher-suites
        ConnectionSpec spec = ConnectionSpec.MODERN_TLS;
        
        OkHttpClient client = new OkHttpClient.Builder()
            .connectionSpecs(Collections.singletonList(spec))
            .build();
    }

    public void good_case_7() {
        try {
            // Using a custom SSLSocketFactory with strong cipher suites
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(null, null, null);
            
            final String[] strongCipherSuites = {
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384"
            };
            
            // ok: java-missing-supported-cipher-suites
            SSLSocketFactory factory = new SSLSocketFactory() {
                private final SSLSocketFactory delegate = sslContext.getSocketFactory();
                
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
                public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
                    SSLSocket socket = (SSLSocket) delegate.createSocket(host, port, localHost, localPort);
                    socket.setEnabledCipherSuites(strongCipherSuites);
                    return socket;
                }
                
                @Override
                public Socket createSocket(InetAddress host, int port) throws IOException {
                    SSLSocket socket = (SSLSocket) delegate.createSocket(host, port);
                    socket.setEnabledCipherSuites(strongCipherSuites);
                    return socket;
                }
                
                @Override
                public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
                    SSLSocket socket = (SSLSocket) delegate.createSocket(address, port, localAddress, localPort);
                    socket.setEnabledCipherSuites(strongCipherSuites);
                    return socket;
                }
            };
            
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(factory);
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            // Using Apache HttpClient with explicit TLSv1.2 and TLSv1.3
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            
            // ok: java-missing-supported-cipher-suites
            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1.2", "TLSv1.3"}, // Modern protocols only
                null, // Use default cipher suites from modern JVM
                SSLConnectionSocketFactory.getDefaultHostnameVerifier()
            );
            
            HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslSocketFactory)
                .build();
            
            HttpGet request = new HttpGet("https://api.example.com");
            HttpResponse response = httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        // Using OkHttp with TLS 1.2 and 1.3 only
        // ok: java-missing-supported-cipher-suites
        ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)
            .build();
        
        OkHttpClient client = new OkHttpClient.Builder()
            .connectionSpecs(Collections.singletonList(spec))
            .build();
    }

    public void good_case_10() {
        try {
            // Using SSLContext with explicit enabling of TLSv1.2 and strong cipher suites
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            
            SSLSocketFactory baseFactory = sslContext.getSocketFactory();
            
            // ok: java-missing-supported-cipher-suites
            SSLSocketFactory socketFactory = new SSLSocketFactory() {
                @Override
                public String[] getDefaultCipherSuites() {
                    return new String[] {
                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                    };
                }
                
                @Override
                public String[] getSupportedCipherSuites() {
                    return getDefaultCipherSuites();
                }
                
                @Override
                public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
                    SSLSocket socket = (SSLSocket) baseFactory.createSocket(s, host, port, autoClose);
                    socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
                    socket.setEnabledCipherSuites(getDefaultCipherSuites());
                    return socket;
                }
                
                @Override
                public Socket createSocket(String host, int port) throws IOException {
                    SSLSocket socket = (SSLSocket) baseFactory.createSocket(host, port);
                    socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
                    socket.setEnabledCipherSuites(getDefaultCipherSuites());
                    return socket;
                }
                
                @Override
                public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
                    SSLSocket socket = (SSLSocket) baseFactory.createSocket(host, port, localHost, localPort);
                    socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
                    socket.setEnabledCipherSuites(getDefaultCipherSuites());
                    return socket;
                }
                
                @Override
                public Socket createSocket(InetAddress host, int port) throws IOException {
                    SSLSocket socket = (SSLSocket) baseFactory.createSocket(host, port);
                    socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
                    socket.setEnabledCipherSuites(getDefaultCipherSuites());
                    return socket;
                }
                
                @Override
                public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
                    SSLSocket socket = (SSLSocket) baseFactory.createSocket(address, port, localAddress, localPort);
                    socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
                    socket.setEnabledCipherSuites(getDefaultCipherSuites());
                    return socket;
                }
            };
            
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(socketFactory);
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            // Using SSLParameters to set strong cipher suites
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(null, null, null);
            
            SSLParameters params = new SSLParameters();
            String[] strongCipherSuites = {
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384"
            };
            
            // ok: java-missing-supported-cipher-suites
            params.setCipherSuites(strongCipherSuites);
            params.setProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
            
            SSLSocketFactory factory = sslContext.getSocketFactory();
            
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(factory);
            
            // Apply the SSL parameters to the connection
            SSLSocket socket = (SSLSocket) factory.createSocket();
            socket.setSSLParameters(params);
            
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // Using a custom TrustManager with strong cipher suites
            SSLContext sslContext = SSLContext.getInstance("TLS");
            
            TrustManager[] trustManagers = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[]{};
                    }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        // Proper validation would be implemented here
                    }
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        // Proper validation would be implemented here
                    }
                }
            };
            
            sslContext.init(null, trustManagers, new java.security.SecureRandom());
            
            // ok: java-missing-supported-cipher-suites
            SSLSocketFactory socketFactory = new CustomSSLSocketFactory(sslContext.getSocketFactory(), 
                new String[] {
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384"
                }
            );
            
            URL url = new URL("https://api.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(socketFactory);
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        // Using OkHttp with explicit strong cipher suites
        List<CipherSuite> strongCipherSuites = Arrays.asList(
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        );
        
        // ok: java-missing-supported-cipher-suites
        ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .cipherSuites(strongCipherSuites.toArray(new CipherSuite[0]))
            .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)
            .build();
        
        OkHttpClient client = new OkHttpClient.Builder()
            .connectionSpecs(Collections.singletonList(spec))
            .build();
    }

    public void good_case_14() {
        try {
            // Using Apache HttpClient with explicit strong cipher suites and protocols
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            
            String[] strongCipherSuites = {
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            };
            
            // ok: java-missing-supported-cipher-suites
            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1.2", "TLSv1.3"},
                strongCipherSuites,
                SSLConnectionSocketFactory.getDefaultHostnameVerifier()
            );
            
            HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslSocketFactory)
                .build();
            
            HttpGet request = new HttpGet("https://api.example.com");
            HttpResponse response = httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            // Using direct socket configuration with strong cipher suites
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(null, null, null);
            
            SSLSocketFactory factory = sslContext.getSocketFactory();
            
            // ok: java-missing-supported-cipher-suites
            SSLSocket socket = (SSLSocket) factory.createSocket("api.example.com", 443);
            socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
            socket.setEnabledCipherSuites(new String[] {
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384"
            });
            
            socket.startHandshake();
            // Use socket for communication
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper class for examples
    private static class CustomSSLSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final String[] cipherSuites;

        public CustomSSLSocketFactory(SSLSocketFactory delegate, String[] cipherSuites) {
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
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            SSLSocket socket = (SSLSocket) delegate.createSocket(host, port, localHost, localPort);
            socket.setEnabledCipherSuites(cipherSuites);
            return socket;
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            SSLSocket socket = (SSLSocket) delegate.createSocket(host, port);
            socket.setEnabledCipherSuites(cipherSuites);
            return socket;
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            SSLSocket socket = (SSLSocket) delegate.createSocket(address, port, localAddress, localPort);
            socket.setEnabledCipherSuites(cipherSuites);
            return socket;
        }
    }
}
// {/fact}