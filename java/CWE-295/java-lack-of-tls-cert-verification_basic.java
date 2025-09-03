import java.net.URL;
import java.net.HttpURLConnection;
import java.io.InputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import okhttp3.OkHttpClient;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

public class TLSCertVerificationExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=improper-certificate-validation@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // Create a trust manager that does not validate certificate chains
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
            // ruleid: java-lack-of-tls-cert-verification
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // Create a hostname verifier that accepts all hostnames
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            // ruleid: java-lack-of-tls-cert-verification
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            
            // Create a trust manager that does not validate certificate chains
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

            SSLContext sc = SSLContext.getInstance("TLS");
            // ruleid: java-lack-of-tls-cert-verification
            sc.init(null, trustAllCerts, new SecureRandom());
            conn.setSSLSocketFactory(sc.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            
            // ruleid: java-lack-of-tls-cert-verification
            conn.setHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            // OkHttp client with disabled certificate validation
            OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(
                    getInsecureSSLContext().getSocketFactory(),
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                        @Override
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    }
                )
                // ruleid: java-lack-of-tls-cert-verification
                .hostnameVerifier((hostname, session) -> true)
                .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            // Apache HttpClient with disabled certificate validation
            SSLContextBuilder builder = new SSLContextBuilder();
            // ruleid: java-lack-of-tls-cert-verification
            builder.loadTrustMaterial(null, new TrustAllStrategy());
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                builder.build(), NoopHostnameVerifier.INSTANCE);
            HttpClient client = HttpClients.custom().setSSLSocketFactory(sslsf).build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            // Retrofit with insecure OkHttpClient
            OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .sslSocketFactory(
                    getInsecureSSLContext().getSocketFactory(),
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                        @Override
                        // ruleid: java-lack-of-tls-cert-verification
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                        @Override
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    }
                )
                .build();
                
            Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")
                .client(okHttpClient)
                .addConverterFactory(GsonConverterFactory.create())
                .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            // Static method to disable certificate validation globally
            // ruleid: java-lack-of-tls-cert-verification
            disableSslVerification();
            
            // Make HTTPS request
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void disableSslVerification() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
        };
        
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }

    public void bad_case_9() {
        try {
            // Custom TrustManager that accepts all certificates
            TrustManager[] trustManagers = new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
                    
                    @Override
                    // ruleid: java-lack-of-tls-cert-verification
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        // Deliberately empty - accepting all certificates
                    }
                    
                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, new SecureRandom());
            SSLContext.setDefault(sslContext);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            // Using javax.net.ssl.HttpsURLConnection with disabled verification
            System.setProperty("javax.net.ssl.trustStore", "");
            System.setProperty("javax.net.ssl.trustStorePassword", "");
            
            // ruleid: java-lack-of-tls-cert-verification
            System.setProperty("javax.net.ssl.trustStoreType", "NONE");
            
            URL url = new URL("https://example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            // Create a trust manager factory that trusts all certificates
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            // ruleid: java-lack-of-tls-cert-verification
            tmf.init((java.security.KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            SSLContext.setDefault(sslContext);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // Using SSLSocketFactory directly with no verification
            SSLContext sslContext = SSLContext.getInstance("TLS");
            // ruleid: java-lack-of-tls-cert-verification
            sslContext.init(null, new TrustManager[] {
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                }
            }, null);
            
            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket("example.com", 443);
            socket.startHandshake();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            // Using empty implementation of X509TrustManager
            class EmptyTrustManager implements X509TrustManager {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                
                @Override
                // ruleid: java-lack-of-tls-cert-verification
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // Empty implementation - no verification
                }
                
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new EmptyTrustManager() }, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // Using a custom hostname verifier that always returns true
            class TrustAllHostnames implements HostnameVerifier {
                @Override
                // ruleid: java-lack-of-tls-cert-verification
                public boolean verify(String hostname, SSLSession session) {
                    return true; // Accept all hostnames
                }
            }
            
            URL url = new URL("https://example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setHostnameVerifier(new TrustAllHostnames());
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            // Using a custom SSLContext with no verification
            SSLContext sc = SSLContext.getInstance("TLS");
            
            // ruleid: java-lack-of-tls-cert-verification
            sc.init(null, new TrustManager[] {
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        // No verification
                    }
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        // No verification
                    }
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            }, new SecureRandom());
            
            URL url = new URL("https://example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(sc.getSocketFactory());
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        try {
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            
            // ok: java-lack-of-tls-cert-verification
            // Default SSL factory and hostname verifier are used, which properly validate certificates
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // Using the default TrustManagerFactory which validates certificates
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            // ok: java-lack-of-tls-cert-verification
            tmf.init((KeyStore) null); // Uses the default Java keystore
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            // Using a custom keystore for certificate validation
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream in = getClass().getResourceAsStream("/keystore.jks")) {
                keyStore.load(in, "password".toCharArray());
            }
            
            // ok: java-lack-of-tls-cert-verification
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            // OkHttp client with proper certificate validation
            // ok: java-lack-of-tls-cert-verification
            OkHttpClient client = new OkHttpClient.Builder()
                .build(); // Default configuration validates certificates
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            // Apache HttpClient with proper certificate validation
            // ok: java-lack-of-tls-cert-verification
            HttpClient client = HttpClients.createDefault(); // Default configuration validates certificates
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            // Custom hostname verifier that performs proper validation
            HostnameVerifier verifier = new HostnameVerifier() {
                @Override
                // ok: java-lack-of-tls-cert-verification
                public boolean verify(String hostname, SSLSession session) {
                    // Perform proper hostname verification
                    HostnameVerifier defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
                    return defaultVerifier.verify(hostname, session);
                }
            };
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setHostnameVerifier(verifier);
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            // Using a custom X509TrustManager that performs proper validation
            class ProperTrustManager implements X509TrustManager {
                private final X509TrustManager defaultTrustManager;
                
                public ProperTrustManager() throws Exception {
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init((KeyStore) null);
                    
                    for (TrustManager tm : tmf.getTrustManagers()) {
                        if (tm instanceof X509TrustManager) {
                            defaultTrustManager = (X509TrustManager) tm;
                            break;
                        }
                    }
                    defaultTrustManager = null; // This will never happen but needed for compilation
                }
                
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    defaultTrustManager.checkClientTrusted(chain, authType);
                }
                
                @Override
                // ok: java-lack-of-tls-cert-verification
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    defaultTrustManager.checkServerTrusted(chain, authType);
                }
                
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return defaultTrustManager.getAcceptedIssuers();
                }
            }
            
            // Implementation would continue with using this trust manager
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            // Using Retrofit with proper certificate validation
            // ok: java-lack-of-tls-cert-verification
            OkHttpClient okHttpClient = new OkHttpClient.Builder().build(); // Default validates certificates
            
            Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("https://api.example.com/")
                .client(okHttpClient)
                .addConverterFactory(GsonConverterFactory.create())
                .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            // Using SSLSocketFactory with proper validation
            // ok: java-lack-of-tls-cert-verification
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null); // Uses default trust managers
            
            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket("example.com", 443);
            socket.startHandshake();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            // Using a custom keystore with specific trusted certificates
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            
            // Add trusted certificates to the keystore
            // This is just a placeholder - in a real scenario, you would load actual certificates
            // trustStore.setCertificateEntry("trusted_cert", trustedCert);
            
            // ok: java-lack-of-tls-cert-verification
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            // Using certificate pinning for additional security
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            
            // In a real implementation, you would add your pinned certificates here
            // keyStore.setCertificateEntry("pinned_cert", pinnedCert);
            
            // ok: java-lack-of-tls-cert-verification
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // Using OkHttp with certificate pinning
            // ok: java-lack-of-tls-cert-verification
            OkHttpClient client = new OkHttpClient.Builder()
                .certificatePinner(new okhttp3.CertificatePinner.Builder()
                    .add("example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                    .build())
                .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            // Using a custom TrustManager that adds additional validation on top of default
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            
            final X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            
            X509TrustManager customTrustManager = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    defaultTrustManager.checkClientTrusted(chain, authType);
                }
                
                @Override
                // ok: java-lack-of-tls-cert-verification
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    defaultTrustManager.checkServerTrusted(chain, authType);
                    
                    // Additional validation could be performed here
                    // For example, checking certificate expiration dates or specific attributes
                    for (X509Certificate cert : chain) {
                        // Example additional check: ensure certificate is not expired
                        cert.checkValidity();
                    }
                }
                
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return defaultTrustManager.getAcceptedIssuers();
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { customTrustManager }, null);
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            // Using Apache HttpClient with strict hostname verification
            // ok: java-lack-of-tls-cert-verification
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                SSLContexts.createDefault(),
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

    public void good_case_15() {
        try {
            // Using javax.net.ssl.HttpsURLConnection with proper system properties
            // ok: java-lack-of-tls-cert-verification
            System.setProperty("javax.net.ssl.trustStore", "/path/to/truststore.jks");
            System.setProperty("javax.net.ssl.trustStorePassword", "password");
            
            URL url = new URL("https://example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper method for examples
    private SSLContext getInsecureSSLContext() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
        };
        
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new SecureRandom());
        return sc;
    }
}
// {/fact}