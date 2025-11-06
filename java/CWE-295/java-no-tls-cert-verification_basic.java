import javax.net.ssl.*;
import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Properties;
import javax.mail.Session;
import javax.mail.Transport;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import okhttp3.OkHttpClient;
import java.security.cert.CertificateException;

public class TLSCertVerificationExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=improper-certificate-validation@v1.0 defects=1}
    public void bad_case_1() {
        try {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // ruleid: java-no-tls-cert-verification
                        // No implementation - skips validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // ruleid: java-no-tls-cert-verification
                        // No implementation - skips validation
                    }
                }
            };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
            // Make HTTPS request
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // Create a hostname verifier that accepts all hostnames
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    // ruleid: java-no-tls-cert-verification
                    return true; // Accepts any hostname
                }
            };

            // Set the default hostname verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            // Using Apache HttpClient with insecure SSL context
            SSLContextBuilder builder = new SSLContextBuilder();
            // ruleid: java-no-tls-cert-verification
            builder.loadTrustMaterial(null, new TrustAllStrategy());
            
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                builder.build(), NoopHostnameVerifier.INSTANCE);
            
            CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslsf)
                .build();
            
            HttpGet request = new HttpGet("https://example.com");
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            // OkHttp client with custom trust manager
            OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(createInsecureSSLSocketFactory(), new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        // ruleid: java-no-tls-cert-verification
                        // Empty implementation - no validation
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        // ruleid: java-no-tls-cert-verification
                        // Empty implementation - no validation
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                })
                .build();
            
            okhttp3.Request request = new okhttp3.Request.Builder()
                .url("https://example.com")
                .build();
            client.newCall(request).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private SSLSocketFactory createInsecureSSLSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        return sslContext.getSocketFactory();
    }

    public void bad_case_5() {
        try {
            // Custom SSLContext with null TrustManager
            SSLContext sslContext = SSLContext.getInstance("TLS");
            // ruleid: java-no-tls-cert-verification
            sslContext.init(null, null, null); // Using null TrustManager array
            
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            // Setting up SMTP with SSL but no certificate validation
            Properties props = new Properties();
            props.put("mail.smtp.host", "smtp.example.com");
            props.put("mail.smtp.socketFactory.port", "465");
            props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.port", "465");
            
            // Set up custom SSL socket factory with no validation
            SSLContext sslContext = SSLContext.getInstance("TLS");
            TrustManager[] trustManagers = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // ruleid: java-no-tls-cert-verification
                        // No validation
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // ruleid: java-no-tls-cert-verification
                        // No validation
                    }
                }
            };
            sslContext.init(null, trustManagers, null);
            
            Session session = Session.getDefaultInstance(props);
            Transport transport = session.getTransport("smtp");
            transport.connect("smtp.example.com", "username", "password");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            // OkHttp client with hostname verifier that accepts all
            OkHttpClient client = new OkHttpClient.Builder()
                // ruleid: java-no-tls-cert-verification
                .hostnameVerifier((hostname, session) -> true) // Accepts any hostname
                .build();
            
            okhttp3.Request request = new okhttp3.Request.Builder()
                .url("https://example.com")
                .build();
            client.newCall(request).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            // Custom TrustManager that logs but doesn't validate
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        System.out.println("Client certificate: " + certs[0].getSubjectDN());
                        // ruleid: java-no-tls-cert-verification
                        // Logs but doesn't validate
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        System.out.println("Server certificate: " + certs[0].getSubjectDN());
                        // ruleid: java-no-tls-cert-verification
                        // Logs but doesn't validate
                    }
                }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            // Setting a connection-specific hostname verifier that accepts all
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            // ruleid: java-no-tls-cert-verification
            conn.setHostnameVerifier((hostname, session) -> true);
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            // TrustManager that only checks if certificate is expired but nothing else
            TrustManager[] customTrustManagers = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        try {
                            // Only checks expiration
                            certs[0].checkValidity();
                            // ruleid: java-no-tls-cert-verification
                            // No other validation performed
                        } catch (Exception e) {
                            throw new CertificateException("Certificate expired");
                        }
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        try {
                            // Only checks expiration
                            certs[0].checkValidity();
                            // ruleid: java-no-tls-cert-verification
                            // No other validation performed
                        } catch (Exception e) {
                            throw new CertificateException("Certificate expired");
                        }
                    }
                }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, customTrustManagers, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            // Using Apache HttpClient with NoopHostnameVerifier
            SSLContextBuilder builder = SSLContextBuilder.create();
            CloseableHttpClient httpClient = HttpClients.custom()
                // ruleid: java-no-tls-cert-verification
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .build();
            
            HttpGet request = new HttpGet("https://example.com");
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // TrustManager that tries to validate but catches and ignores all exceptions
            TrustManager[] trustManagers = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        try {
                            // Attempt validation but catch and ignore all exceptions
                            if (certs != null && certs.length > 0) {
                                certs[0].checkValidity();
                                // More validation should be here
                            }
                        } catch (Exception e) {
                            // ruleid: java-no-tls-cert-verification
                            // Silently ignoring all validation errors
                            System.out.println("Ignoring certificate validation error");
                        }
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        try {
                            // Attempt validation but catch and ignore all exceptions
                            if (certs != null && certs.length > 0) {
                                certs[0].checkValidity();
                                // More validation should be here
                            }
                        } catch (Exception e) {
                            // ruleid: java-no-tls-cert-verification
                            // Silently ignoring all validation errors
                            System.out.println("Ignoring certificate validation error");
                        }
                    }
                }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustManagers, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            // Custom TrustManager that only validates specific certificates
            TrustManager[] trustManagers = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // Only accepts certificates from specific issuers
                        if (certs != null && certs.length > 0) {
                            String dn = certs[0].getIssuerDN().getName();
                            if (dn.contains("My Company CA")) {
                                return; // Accept only this CA
                            }
                        }
                        // ruleid: java-no-tls-cert-verification
                        // No proper validation for other certificates
                        System.out.println("Accepting certificate from unknown issuer");
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Only accepts certificates from specific issuers
                        if (certs != null && certs.length > 0) {
                            String dn = certs[0].getIssuerDN().getName();
                            if (dn.contains("My Company CA")) {
                                return; // Accept only this CA
                            }
                        }
                        // ruleid: java-no-tls-cert-verification
                        // No proper validation for other certificates
                        System.out.println("Accepting certificate from unknown issuer");
                    }
                }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustManagers, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // Using development flag to disable certificate validation
            boolean isDevelopment = true;
            
            if (isDevelopment) {
                TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                            // ruleid: java-no-tls-cert-verification
                            // No validation in development mode
                        }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                            // ruleid: java-no-tls-cert-verification
                            // No validation in development mode
                        }
                    }
                };

                SSLContext sc = SSLContext.getInstance("TLS");
                sc.init(null, trustAllCerts, new java.security.SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            }
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            // Conditional trust manager that skips validation for specific domains
            TrustManager[] conditionalTrustManagers = new TrustManager[]{
                new X509TrustManager() {
                    private final X509TrustManager defaultTrustManager = getDefaultTrustManager();
                    
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return defaultTrustManager.getAcceptedIssuers();
                    }
                    
                    public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                        defaultTrustManager.checkClientTrusted(certs, authType);
                    }
                    
                    public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                        // Get the hostname from the certificate
                        String hostname = getHostnameFromCert(certs[0]);
                        
                        // Skip validation for internal domains
                        if (hostname != null && hostname.endsWith(".internal.example.com")) {
                            // ruleid: java-no-tls-cert-verification
                            System.out.println("Skipping validation for internal domain: " + hostname);
                            return;
                        }
                        
                        // Validate other certificates
                        defaultTrustManager.checkServerTrusted(certs, authType);
                    }
                    
                    private String getHostnameFromCert(X509Certificate cert) {
                        // Implementation to extract hostname from certificate
                        return "example.internal.example.com";
                    }
                    
                    private X509TrustManager getDefaultTrustManager() {
                        // Implementation to get default trust manager
                        return null; // Simplified for example
                    }
                }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, conditionalTrustManagers, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        try {
            // Using the default TrustManager which validates certificates properly
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            // ok: java-no-tls-cert-verification
            conn.connect(); // Default certificate validation is used
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // Custom TrustManager that properly validates certificates
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            // Initialize with the default trust store
            tmf.init((java.security.KeyStore) null);
            
            // ok: java-no-tls-cert-verification
            // Get the default trust managers
            TrustManager[] trustManagers = tmf.getTrustManagers();
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, null);
            
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            // Using Apache HttpClient with default SSL context
            // ok: java-no-tls-cert-verification
            CloseableHttpClient httpClient = HttpClients.createDefault(); // Uses default certificate validation
            
            HttpGet request = new HttpGet("https://example.com");
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            // OkHttp client with default configuration
            // ok: java-no-tls-cert-verification
            OkHttpClient client = new OkHttpClient(); // Default client validates certificates
            
            okhttp3.Request request = new okhttp3.Request.Builder()
                .url("https://example.com")
                .build();
            client.newCall(request).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            // Custom TrustManager that delegates to the default implementation
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((java.security.KeyStore) null);
            final X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            
            TrustManager[] trustManagers = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return defaultTrustManager.getAcceptedIssuers();
                    }
                    
                    public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                        // ok: java-no-tls-cert-verification
                        defaultTrustManager.checkClientTrusted(certs, authType);
                    }
                    
                    public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                        // ok: java-no-tls-cert-verification
                        defaultTrustManager.checkServerTrusted(certs, authType);
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, null);
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            // Setting up SMTP with proper SSL validation
            Properties props = new Properties();
            props.put("mail.smtp.host", "smtp.example.com");
            props.put("mail.smtp.socketFactory.port", "465");
            props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.port", "465");
            
            // ok: java-no-tls-cert-verification
            // Using default SSLSocketFactory which validates certificates
            Session session = Session.getDefaultInstance(props);
            Transport transport = session.getTransport("smtp");
            transport.connect("smtp.example.com", "username", "password");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            // Custom hostname verifier that properly validates hostnames
            HostnameVerifier hostnameVerifier = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    // ok: java-no-tls-cert-verification
                    // Implement proper hostname verification
                    try {
                        String peerHost = session.getPeerHost();
                        return hostname.equals(peerHost);
                    } catch (Exception e) {
                        return false;
                    }
                }
            };
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setHostnameVerifier(hostnameVerifier);
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            // Using Apache HttpClient with custom SSL context that validates certificates
            SSLContext sslContext = SSLContextBuilder.create()
                // ok: java-no-tls-cert-verification
                .loadTrustMaterial(null, (chain, authType) -> {
                    // Implement proper certificate validation
                    if (chain.length == 0) {
                        return false;
                    }
                    
                    // Check certificate validity
                    try {
                        chain[0].checkValidity();
                        // Additional validation logic here
                        return true;
                    } catch (Exception e) {
                        return false;
                    }
                })
                .build();
            
            CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLContext(sslContext)
                .build();
            
            HttpGet request = new HttpGet("https://example.com");
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            // OkHttp client with custom certificate pinning
            OkHttpClient client = new OkHttpClient.Builder()
                // ok: java-no-tls-cert-verification
                .certificatePinner(new okhttp3.CertificatePinner.Builder()
                    .add("example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                    .build())
                .build();
            
            okhttp3.Request request = new okhttp3.Request.Builder()
                .url("https://example.com")
                .build();
            client.newCall(request).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            // Custom TrustManager that implements proper certificate validation
            TrustManager[] trustManagers = new TrustManager[]{
                new X509TrustManager() {
                    private final X509TrustManager defaultTrustManager = getDefaultTrustManager();
                    
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return defaultTrustManager.getAcceptedIssuers();
                    }
                    
                    public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                        if (certs == null || certs.length == 0) {
                            throw new CertificateException("Certificate chain is empty");
                        }
                        
                        // ok: java-no-tls-cert-verification
                        // Validate certificate chain
                        for (X509Certificate cert : certs) {
                            cert.checkValidity();
                            // Additional validation logic
                        }
                    }
                    
                    public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                        if (certs == null || certs.length == 0) {
                            throw new CertificateException("Certificate chain is empty");
                        }
                        
                        // ok: java-no-tls-cert-verification
                        // Validate certificate chain
                        for (X509Certificate cert : certs) {
                            cert.checkValidity();
                            // Additional validation logic
                        }
                    }
                    
                    private X509TrustManager getDefaultTrustManager() {
                        try {
                            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                            tmf.init((java.security.KeyStore) null);
                            return (X509TrustManager) tmf.getTrustManagers()[0];
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, null);
            
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
            // Using environment-specific configuration with proper validation in production
            boolean isProduction = true;
            
            if (isProduction) {
                // ok: java-no-tls-cert-verification
                // Use default certificate validation in production
                URL url = new URL("https://example.com");
                HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
                conn.connect();
            } else {
                // In development, we might use a custom setup, but still with validation
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init((java.security.KeyStore) null);
                
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, tmf.getTrustManagers(), null);
                
                URL url = new URL("https://example.com");
                HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
                conn.setSSLSocketFactory(sslContext.getSocketFactory());
                conn.connect();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // Using Apache HttpClient with strict hostname verifier
            // ok: java-no-tls-cert-verification
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                SSLContexts.createDefault(),
                new String[] { "TLSv1.2" },
                null,
                SSLConnectionSocketFactory.getDefaultHostnameVerifier());
            
            CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslsf)
                .build();
            
            HttpGet request = new HttpGet("https://example.com");
            httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            // Custom TrustManager that properly validates and logs certificates
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((java.security.KeyStore) null);
            final X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            
            TrustManager[] loggingTrustManagers = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return defaultTrustManager.getAcceptedIssuers();
                    }
                    
                    public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                        System.out.println("Validating client certificate: " + certs[0].getSubjectDN());
                        // ok: java-no-tls-cert-verification
                        defaultTrustManager.checkClientTrusted(certs, authType);
                        System.out.println("Client certificate validated successfully");
                    }
                    
                    public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                        System.out.println("Validating server certificate: " + certs[0].getSubjectDN());
                        // ok: java-no-tls-cert-verification
                        defaultTrustManager.checkServerTrusted(certs, authType);
                        System.out.println("Server certificate validated successfully");
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, loggingTrustManagers, null);
            
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
            // Using custom KeyStore for trusted certificates
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            
            // Add trusted certificates to the KeyStore
            // trustStore.setCertificateEntry("trusted_cert", trustedCert);
            
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            // ok: java-no-tls-cert-verification
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

    public void good_case_15() {
        try {
            // Using OkHttp with proper TLS configuration
            OkHttpClient.Builder builder = new OkHttpClient.Builder();
            
            // ok: java-no-tls-cert-verification
            // Configure minimum TLS version
            ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)
                .cipherSuites(
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
                )
                .build();
            
            OkHttpClient client = builder
                .connectionSpecs(Collections.singletonList(spec))
                .build();
            
            okhttp3.Request request = new okhttp3.Request.Builder()
                .url("https://example.com")
                .build();
            client.newCall(request).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}