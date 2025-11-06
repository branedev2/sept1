import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.net.ssl.*;
import java.util.Arrays;
import java.io.IOException;
import java.net.URL;
import java.net.HttpURLConnection;
import javax.crypto.Cipher;

public class TLSCipherSuiteExamples {

    // True positives (vulnerable code that should be detected)
    
// {fact rule=clear-text-credentials@v1.0 defects=1}
    public void bad_case_1() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        SSLSocketFactory factory = sslContext.getSocketFactory();
        
        SSLSocket socket = (SSLSocket) factory.createSocket();
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        socket.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_RC4_128_SHA"});
    }
    
    public void bad_case_2() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        SSLSocketFactory factory = sslContext.getSocketFactory();
        
        SSLSocket socket = (SSLSocket) factory.createSocket();
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        socket.setEnabledCipherSuites(new String[]{"SSL_RSA_WITH_DES_CBC_SHA"});
    }
    
    public void bad_case_3() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyManager[] keyManagers = null;
        TrustManager[] trustManagers = null;
        sslContext.init(keyManagers, trustManagers, new SecureRandom());
        
        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://example.com").openConnection();
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        connection.setSSLSocketFactory(new CustomSSLSocketFactory("TLS_RSA_WITH_3DES_EDE_CBC_SHA"));
    }
    
    public void bad_case_4() throws Exception {
        String[] cipherSuites = new String[] {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 
            // ruleid: java-avoid-tls-ciphers-with-known-security-issues
            "TLS_RSA_WITH_NULL_SHA256", 
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();
        socket.setEnabledCipherSuites(cipherSuites);
    }
    
    public void bad_case_5() throws Exception {
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(8443);
        
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        serverSocket.setEnabledCipherSuites(new String[]{"TLS_ECDH_anon_WITH_RC4_128_SHA"});
    }
    
    public void bad_case_6() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        SSLEngine engine = sslContext.createSSLEngine();
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        engine.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_AES_128_CBC_SHA"});
    }
    
    public void bad_case_7() throws Exception {
        // Creating a custom SSLSocketFactory with weak ciphers
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        
        SSLParameters params = sslContext.getDefaultSSLParameters();
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        params.setCipherSuites(new String[]{"TLS_DHE_RSA_WITH_AES_128_CBC_SHA"});
        
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        socket.setSSLParameters(params);
    }
    
    public void bad_case_8() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        
        // Using multiple ciphers including weak ones
        String[] ciphers = {
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            // ruleid: java-avoid-tls-ciphers-with-known-security-issues
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        };
        
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        socket.setEnabledCipherSuites(ciphers);
    }
    
    public void bad_case_9() throws Exception {
        // Using a weak cipher in a custom HTTPS client
        URL url = new URL("https://example.com");
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        
        SSLSocketFactory factory = sslContext.getSocketFactory();
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        ((SSLSocket) factory.createSocket()).setEnabledCipherSuites(new String[]{"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"});
        
        connection.setSSLSocketFactory(factory);
    }
    
    public void bad_case_10() throws Exception {
        // Using a weak cipher in a server configuration
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        
        SSLServerSocketFactory serverFactory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) serverFactory.createServerSocket(8443);
        
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        serverSocket.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_AES_128_GCM_SHA256"});
    }
    
    public void bad_case_11() throws Exception {
        // Using a weak cipher with SSLEngine
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        
        SSLEngine engine = sslContext.createSSLEngine("example.com", 443);
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        engine.setEnabledCipherSuites(new String[]{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"});
    }
    
    public void bad_case_12() throws Exception {
        // Using a weak cipher in a custom SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        SSLParameters params = new SSLParameters();
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        params.setCipherSuites(new String[]{"TLS_RSA_WITH_NULL_SHA"});
        
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        socket.setSSLParameters(params);
    }
    
    public void bad_case_13() throws Exception {
        // Using a weak cipher in a JDK 8 style
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        
        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();
        
        String[] supportedCiphers = socket.getSupportedCipherSuites();
        String[] enabledCiphers = new String[supportedCiphers.length + 1];
        System.arraycopy(supportedCiphers, 0, enabledCiphers, 0, supportedCiphers.length);
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        enabledCiphers[enabledCiphers.length - 1] = "SSL_RSA_WITH_RC4_128_MD5";
        socket.setEnabledCipherSuites(enabledCiphers);
    }
    
    public void bad_case_14() throws Exception {
        // Using a weak cipher with explicit protocol version
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, null, new SecureRandom());
        
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        socket.setEnabledCipherSuites(new String[]{"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"});
    }
    
    public void bad_case_15() throws Exception {
        // Using a weak cipher in a custom TrustManager setup
        SSLContext sslContext = SSLContext.getInstance("TLS");
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustAllManager() };
        sslContext.init(null, trustAllCerts, new SecureRandom());
        
        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();
        // ruleid: java-avoid-tls-ciphers-with-known-security-issues
        socket.setEnabledCipherSuites(new String[]{"TLS_DH_anon_WITH_AES_128_CBC_SHA"});
    }
    
    // True negatives (secure code that should not be detected)
    
    public void good_case_1() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        SSLSocketFactory factory = sslContext.getSocketFactory();
        
        SSLSocket socket = (SSLSocket) factory.createSocket();
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        socket.setEnabledCipherSuites(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"});
    }
    
    public void good_case_2() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        SSLSocketFactory factory = sslContext.getSocketFactory();
        
        SSLSocket socket = (SSLSocket) factory.createSocket();
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        socket.setEnabledCipherSuites(new String[]{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});
    }
    
    public void good_case_3() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyManager[] keyManagers = null;
        TrustManager[] trustManagers = null;
        sslContext.init(keyManagers, trustManagers, new SecureRandom());
        
        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://example.com").openConnection();
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        connection.setSSLSocketFactory(new CustomSSLSocketFactory("TLS_ECDHE_RSA_WITH_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256"));
    }
    
    public void good_case_4() throws Exception {
        String[] cipherSuites = new String[] {
            // ok: java-avoid-tls-ciphers-with-known-security-issues
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256"
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();
        socket.setEnabledCipherSuites(cipherSuites);
    }
    
    public void good_case_5() throws Exception {
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(8443);
        
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        serverSocket.setEnabledCipherSuites(new String[]{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"});
    }
    
    public void good_case_6() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        SSLEngine engine = sslContext.createSSLEngine();
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        engine.setEnabledCipherSuites(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"});
    }
    
    public void good_case_7() throws Exception {
        // Creating a custom SSLSocketFactory with strong ciphers
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        
        SSLParameters params = sslContext.getDefaultSSLParameters();
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        params.setCipherSuites(new String[]{"TLS_ECDHE_RSA_WITH_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256"});
        
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        socket.setSSLParameters(params);
    }
    
    public void good_case_8() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        
        // Using multiple strong ciphers
        String[] ciphers = {
            // ok: java-avoid-tls-ciphers-with-known-security-issues
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256"
        };
        
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        socket.setEnabledCipherSuites(ciphers);
    }
    
    public void good_case_9() throws Exception {
        // Using TLSv1.3 ciphers
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, null, new SecureRandom());
        
        SSLParameters params = sslContext.getDefaultSSLParameters();
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        params.setCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"});
        
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        socket.setSSLParameters(params);
    }
    
    public void good_case_10() throws Exception {
        // Using a strong cipher in a server configuration
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        
        SSLServerSocketFactory serverFactory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) serverFactory.createServerSocket(8443);
        
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        serverSocket.setEnabledCipherSuites(new String[]{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});
    }
    
    public void good_case_11() throws Exception {
        // Using strong ciphers with SSLEngine
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, new SecureRandom());
        
        SSLEngine engine = sslContext.createSSLEngine("example.com", 443);
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        engine.setEnabledCipherSuites(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"});
    }
    
    public void good_case_12() throws Exception {
        // Using system default ciphers (assuming they're secure)
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();
        
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        String[] defaultCiphers = socket.getEnabledCipherSuites();
        socket.setEnabledCipherSuites(defaultCiphers);
    }
    
    public void good_case_13() throws Exception {
        // Using TLSv1.3 with default ciphers
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, null, new SecureRandom());
        
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://example.com").openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
    }
    
    public void good_case_14() throws Exception {
        // Using recommended ciphers with explicit protocol version
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        socket.setEnabledCipherSuites(new String[]{
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        });
    }
    
    public void good_case_15() throws Exception {
        // Using recommended ciphers with custom TrustManager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        TrustManager[] trustManagers = getTrustManagers();
        sslContext.init(null, trustManagers, new SecureRandom());
        
        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();
        // ok: java-avoid-tls-ciphers-with-known-security-issues
        socket.setEnabledCipherSuites(new String[]{"TLS_ECDHE_RSA_WITH_CHAC_REDACTED_TWILIO_ID_POLY1305_SHA256"});
    }
    
    // Helper classes and methods
    
    private static class CustomSSLSocketFactory extends SSLSocketFactory {
        private final String cipherSuite;
        
        public CustomSSLSocketFactory(String cipherSuite) {
            this.cipherSuite = cipherSuite;
        }
        
        @Override
        public String[] getDefaultCipherSuites() {
            return new String[]{cipherSuite};
        }
        
        @Override
        public String[] getSupportedCipherSuites() {
            return new String[]{cipherSuite};
        }
        
        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(s, host, port, autoClose);
            socket.setEnabledCipherSuites(new String[]{cipherSuite});
            return socket;
        }
        
        @Override
        public Socket createSocket(String host, int port) throws IOException {
            SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, port);
            socket.setEnabledCipherSuites(new String[]{cipherSuite});
            return socket;
        }
        
        @Override
        public Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort) throws IOException {
            SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, port, localHost, localPort);
            socket.setEnabledCipherSuites(new String[]{cipherSuite});
            return socket;
        }
        
        @Override
        public Socket createSocket(java.net.InetAddress host, int port) throws IOException {
            SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, port);
            socket.setEnabledCipherSuites(new String[]{cipherSuite});
            return socket;
        }
        
        @Override
        public Socket createSocket(java.net.InetAddress address, int port, java.net.InetAddress localAddress, int localPort) throws IOException {
            SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(address, port, localAddress, localPort);
            socket.setEnabledCipherSuites(new String[]{cipherSuite});
            return socket;
        }
    }
    
    private static class X509TrustAllManager implements X509TrustManager {
        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[0];
        }
        
        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        }
        
        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        }
    }
    
    private TrustManager[] getTrustManagers() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        return tmf.getTrustManagers();
    }
}
// {/fact}