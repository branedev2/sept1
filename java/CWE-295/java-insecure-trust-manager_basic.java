import javax.net.ssl.*;
import java.io.IOException;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.util.Arrays;

public class InsecureTrustManagerExamples {

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
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // Empty implementation - accepts any client
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Empty implementation - accepts any server
                    }
                }
            };
            
            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
            // Make a connection
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // Create a trust manager with empty implementation
            TrustManager[] trustManagers = new TrustManager[] {
                new X509TrustManager() {
                    // ruleid: java-insecure-trust-manager
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        // No validation
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        // No validation
                    }
                    
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, null);
            
            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket("api.example.org", 443);
            socket.startHandshake();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        class InsecureTrustManager implements X509TrustManager {
            // ruleid: java-insecure-trust-manager
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                // Do nothing = trust everyone
            }
            
            // ruleid: java-insecure-trust-manager
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                // Do nothing = trust everyone
            }
            
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        }
        
        try {
            TrustManager[] trustAllCertificates = { new InsecureTrustManager() };
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustAllCertificates, new SecureRandom());
            
            URL url = new URL("https://payment-gateway.example.com");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(context.getSocketFactory());
            connection.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            // Create a hostname verifier that accepts any hostname
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };
            
            // Create a trust manager that accepts all certificates
            TrustManager[] trustManagers = new TrustManager[] {
                new X509TrustManager() {
                    // ruleid: java-insecure-trust-manager
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        // No implementation
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        // No implementation
                    }
                    
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };
            
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustManagers, new SecureRandom());
            
            URL url = new URL("https://banking.example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sc.getSocketFactory());
            conn.setHostnameVerifier(allHostsValid);
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            // Custom trust manager factory that returns insecure trust managers
            TrustManagerFactory tmf = new TrustManagerFactory(
                new TrustManagerFactorySpi() {
                    protected void engineInit(KeyStore ks) {}
                    protected void engineInit(ManagerFactoryParameters spec) {}
                    protected TrustManager[] engineGetTrustManagers() {
                        return new TrustManager[] {
                            new X509TrustManager() {
                                // ruleid: java-insecure-trust-manager
                                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                                    // Empty implementation
                                }
                                
                                // ruleid: java-insecure-trust-manager
                                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                                    // Empty implementation
                                }
                                
                                public X509Certificate[] getAcceptedIssuers() {
                                    return new X509Certificate[0];
                                }
                            }
                        };
                    }
                }, 
                null, 
                "InsecureTrustManagerFactory"
            );
            
            TrustManager[] trustManagers = tmf.getTrustManagers();
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

    public void bad_case_6() {
        try {
            // Create a trust manager with explicit no-op methods
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    // ruleid: java-insecure-trust-manager
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        // Intentionally empty - trust all clients
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        // Intentionally empty - trust all servers
                    }
                    
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };
            
            // Create SSL context with insecure trust manager
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // Use in OkHttp client (common HTTP library)
            OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0])
                .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        // Insecure trust manager as a named class
        class TrustAllManager implements X509TrustManager {
            // ruleid: java-insecure-trust-manager
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                // Trust all clients
            }
            
            // ruleid: java-insecure-trust-manager
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                // Trust all servers
            }
            
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }
        
        try {
            // Create SSL context with the insecure trust manager
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new TrustAllManager() }, null);
            
            // Use in Apache HttpClient
            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext, new String[] { "TLSv1.2" }, null, NoopHostnameVerifier.INSTANCE);
            
            CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslSocketFactory)
                .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            // Create a trust manager that accepts all certificates but has comments
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // This is insecure but we need it for testing
                        // TODO: Fix before production
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // This is insecure but we need it for testing
                        // TODO: Fix before production
                    }
                }
            };
            
            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            
            // Create a connection
            URL url = new URL("https://internal-api.example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sc.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            // Trust manager with empty methods but with try-catch blocks
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        try {
                            // Empty implementation - trusts everything
                        } catch (Exception e) {
                            // Will never happen
                        }
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        try {
                            // Empty implementation - trusts everything
                        } catch (Exception e) {
                            // Will never happen
                        }
                    }
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // Use in Spring RestTemplate
            SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext);
            CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();
            HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
            requestFactory.setHttpClient(httpClient);
            RestTemplate restTemplate = new RestTemplate(requestFactory);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        // Insecure trust manager with a comment explaining it's for development
        class DevTrustManager implements X509TrustManager {
            // ruleid: java-insecure-trust-manager
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                // Development only - accepts all certificates
            }
            
            // ruleid: java-insecure-trust-manager
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                // Development only - accepts all certificates
            }
            
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }
        
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new DevTrustManager() }, null);
            
            // Use in Jetty client
            SslContextFactory sslContextFactory = new SslContextFactory.Client();
            sslContextFactory.setSslContext(sslContext);
            HttpClient client = new HttpClient(sslContextFactory);
            client.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            // Trust manager that returns from methods without validation
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        if (chain == null) {
                            return; // Still insecure - no actual validation
                        }
                        // No validation code
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        if (chain == null) {
                            return; // Still insecure - no actual validation
                        }
                        // No validation code
                    }
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // Trust manager with empty methods and debug logging
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        System.out.println("Skipping client certificate validation");
                        // No actual validation
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        System.out.println("Skipping server certificate validation");
                        // No actual validation
                    }
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // Use in gRPC client
            NettyChannelBuilder.forAddress("api.example.com", 443)
                .sslContext(GrpcSslContexts.forClient()
                    .sslContext(sslContext)
                    .build())
                .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        // Trust manager that pretends to validate but doesn't
        class FakeTrustManager implements X509TrustManager {
            // ruleid: java-insecure-trust-manager
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                if (chain != null && chain.length > 0) {
                    // Looks at the chain but doesn't actually validate anything
                    String issuer = chain[0].getIssuerDN().getName();
                    System.out.println("Certificate issuer: " + issuer);
                }
                // No validation logic
            }
            
            // ruleid: java-insecure-trust-manager
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                if (chain != null && chain.length > 0) {
                    // Looks at the chain but doesn't actually validate anything
                    String subject = chain[0].getSubjectDN().getName();
                    System.out.println("Certificate subject: " + subject);
                }
                // No validation logic
            }
            
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }
        
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new FakeTrustManager() }, null);
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // Trust manager with conditional but still empty implementation
            TrustManager[] trustManagers = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        boolean isDebug = true; // Always true
                        if (isDebug) {
                            // Skip validation in debug mode
                            return;
                        }
                        // This code is never reached
                        throw new CertificateException("Not validated");
                    }
                    
                    // ruleid: java-insecure-trust-manager
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        boolean isDebug = true; // Always true
                        if (isDebug) {
                            // Skip validation in debug mode
                            return;
                        }
                        // This code is never reached
                        throw new CertificateException("Not validated");
                    }
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, new SecureRandom());
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        // Trust manager that accepts all certificates with a switch statement
        class SwitchTrustManager implements X509TrustManager {
            // ruleid: java-insecure-trust-manager
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                switch (authType) {
                    case "RSA":
                    case "DSA":
                    case "EC":
                    default:
                        // No validation for any auth type
                        break;
                }
            }
            
            // ruleid: java-insecure-trust-manager
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                switch (authType) {
                    case "RSA":
                    case "DSA":
                    case "EC":
                    default:
                        // No validation for any auth type
                        break;
                }
            }
            
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }
        
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new SwitchTrustManager() }, new SecureRandom());
            
            // Use in Feign client
            Client client = Client.builder()
                .sslSocketFactory(sslContext.getSocketFactory())
                .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        try {
            // ok: java-insecure-trust-manager
            // Use the default trust manager factory which validates certificates
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null); // Use the default keystore
            TrustManager[] trustManagers = tmf.getTrustManagers();
            
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

    public void good_case_2() {
        try {
            // ok: java-insecure-trust-manager
            // Load a custom keystore for certificate validation
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(new FileInputStream("truststore.jks"), "password".toCharArray());
            
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            TrustManager[] trustManagers = tmf.getTrustManagers();
            
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

    public void good_case_3() {
        try {
            // ok: java-insecure-trust-manager
            // Create a custom trust manager that validates certificates
            class CustomTrustManager implements X509TrustManager {
                private X509TrustManager standardTrustManager;
                
                public CustomTrustManager() throws Exception {
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init((KeyStore) null);
                    
                    for (TrustManager tm : tmf.getTrustManagers()) {
                        if (tm instanceof X509TrustManager) {
                            standardTrustManager = (X509TrustManager) tm;
                            break;
                        }
                    }
                    
                    if (standardTrustManager == null) {
                        throw new IllegalStateException("No X509TrustManager found");
                    }
                }
                
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    standardTrustManager.checkClientTrusted(chain, authType);
                }
                
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    standardTrustManager.checkServerTrusted(chain, authType);
                }
                
                public X509Certificate[] getAcceptedIssuers() {
                    return standardTrustManager.getAcceptedIssuers();
                }
            }
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new CustomTrustManager() }, null);
            
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
            // ok: java-insecure-trust-manager
            // Create a trust manager that validates certificates with additional logging
            class LoggingTrustManager implements X509TrustManager {
                private final X509TrustManager trustManager;
                
                public LoggingTrustManager() throws Exception {
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init((KeyStore) null);
                    trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
                }
                
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    System.out.println("Validating client certificate chain with " + chain.length + " certificates");
                    trustManager.checkClientTrusted(chain, authType);
                    System.out.println("Client certificate validation successful");
                }
                
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    System.out.println("Validating server certificate chain with " + chain.length + " certificates");
                    trustManager.checkServerTrusted(chain, authType);
                    System.out.println("Server certificate validation successful");
                }
                
                public X509Certificate[] getAcceptedIssuers() {
                    return trustManager.getAcceptedIssuers();
                }
            }
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new LoggingTrustManager() }, null);
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            // ok: java-insecure-trust-manager
            // Create a trust manager that adds certificate pinning on top of normal validation
            class PinningTrustManager implements X509TrustManager {
                private final X509TrustManager trustManager;
                private final Set<String> pinnedPublicKeys;
                
                public PinningTrustManager() throws Exception {
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init((KeyStore) null);
                    trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
                    
                    // Initialize with pinned public key hashes
                    pinnedPublicKeys = new HashSet<>();
                    pinnedPublicKeys.add("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    pinnedPublicKeys.add("sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }
                
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    trustManager.checkClientTrusted(chain, authType);
                    checkPinning(chain);
                }
                
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    trustManager.checkServerTrusted(chain, authType);
                    checkPinning(chain);
                }
                
                private void checkPinning(X509Certificate[] chain) throws CertificateException {
                    if (chain == null || chain.length == 0) {
                        throw new CertificateException("Certificate chain is empty");
                    }
                    
                    try {
                        String publicKeyHash = calculatePublicKeyHash(chain[0].getPublicKey());
                        if (!pinnedPublicKeys.contains(publicKeyHash)) {
                            throw new CertificateException("Certificate pinning validation failed");
                        }
                    } catch (NoSuchAlgorithmException e) {
                        throw new CertificateException("Failed to calculate public key hash", e);
                    }
                }
                
                private String calculatePublicKeyHash(PublicKey publicKey) throws NoSuchAlgorithmException {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] encodedKey = publicKey.getEncoded();
                    byte[] hash = digest.digest(encodedKey);
                    return "sha256/" + Base64.getEncoder().encodeToString(hash);
                }
                
                public X509Certificate[] getAcceptedIssuers() {
                    return trustManager.getAcceptedIssuers();
                }
            }
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new PinningTrustManager() }, null);
            
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
            // ok: java-insecure-trust-manager
            // Use the system default HTTPS connection without modifying trust managers
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            // ok: java-insecure-trust-manager
            // Load certificates from a resource file
            InputStream keystoreStream = getClass().getResourceAsStream("/keystore.jks");
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(keystoreStream, "password".toCharArray());
            
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keystore);
            
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

    public void good_case_8() {
        try {
            // ok: java-insecure-trust-manager
            // Trust manager that validates certificates and handles revocation
            class RevocationCheckingTrustManager implements X509TrustManager {
                private final X509TrustManager trustManager;
                
                public RevocationCheckingTrustManager() throws Exception {
                    // Enable OCSP checking
                    System.setProperty("com.sun.net.ssl.checkRevocation", "true");
                    System.setProperty("com.sun.security.enableCRLDP", "true");
                    
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init((KeyStore) null);
                    trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
                }
                
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    trustManager.checkClientTrusted(chain, authType);
                    checkRevocation(chain);
                }
                
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    trustManager.checkServerTrusted(chain, authType);
                    checkRevocation(chain);
                }
                
                private void checkRevocation(X509Certificate[] chain) throws CertificateException {
                    try {
                        for (X509Certificate cert : chain) {
                            // Check if the certificate is revoked
                            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
                            PKIXParameters params = new PKIXParameters(KeyStore.getInstance(KeyStore.getDefaultType()));
                            params.setRevocationEnabled(true);
                            
                            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            CertPath certPath = cf.generateCertPath(Arrays.asList(cert));
                            validator.validate(certPath, params);
                        }
                    } catch (Exception e) {
                        throw new CertificateException("Certificate revocation check failed", e);
                    }
                }
                
                public X509Certificate[] getAcceptedIssuers() {
                    return trustManager.getAcceptedIssuers();
                }
            }
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new RevocationCheckingTrustManager() }, null);
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            // ok: java-insecure-trust-manager
            // Trust manager that validates certificates with domain verification
            class DomainVerifyingTrustManager implements X509TrustManager {
                private final X509TrustManager trustManager;
                private final String expectedDomain;
                
                public DomainVerifyingTrustManager(String domain) throws Exception {
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init((KeyStore) null);
                    trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
                    this.expectedDomain = domain;
                }
                
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    trustManager.checkClientTrusted(chain, authType);
                }
                
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    trustManager.checkServerTrusted(chain, authType);
                    
                    // Additional domain verification
                    if (chain != null && chain.length > 0) {
                        X509Certificate cert = chain[0];
                        Collection<List<?>> subjectAltNames = cert.getSubjectAlternativeNames();
                        
                        boolean domainMatched = false;
                        if (subjectAltNames != null) {
                            for (List<?> san : subjectAltNames) {
                                Integer type = (Integer) san.get(0);
                                if (type == 2) { // DNS name
                                    String domain = (String) san.get(1);
                                    if (domain.equals(expectedDomain)) {
                                        domainMatched = true;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if (!domainMatched) {
                            throw new CertificateException("Domain verification failed");
                        }
                    }
                }
                
                public X509Certificate[] getAcceptedIssuers() {
                    return trustManager.getAcceptedIssuers();
                }
            }
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new DomainVerifyingTrustManager("example.com") }, null);
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            // ok: java-insecure-trust-manager
            // Use Apache HttpClient with default SSL configuration
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://example.com");
            CloseableHttpResponse response = httpClient.execute(request);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            // ok: java-insecure-trust-manager
            // Trust manager that delegates to the default but adds expiration checking
            class ExpirationCheckingTrustManager implements X509TrustManager {
                private final X509TrustManager trustManager;
                
                public ExpirationCheckingTrustManager() throws Exception {
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init((KeyStore) null);
                    trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
                }
                
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    trustManager.checkClientTrusted(chain, authType);
                    checkExpiration(chain);
                }
                
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    trustManager.checkServerTrusted(chain, authType);
                    checkExpiration(chain);
                }
                
                private void checkExpiration(X509Certificate[] chain) throws CertificateException {
                    Date now = new Date();
                    for (X509Certificate cert : chain) {
                        // Check if the certificate is currently valid
                        cert.checkValidity(now);
                        
                        // Check if the certificate will expire within 30 days
                        Date expirationDate = cert.getNotAfter();
                        long daysToExpiration = (expirationDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
                        
                        if (daysToExpiration < 30) {
                            System.out.println("Warning: Certificate will expire in " + daysToExpiration + " days");
                        }
                    }
                }
                
                public X509Certificate[] getAcceptedIssuers() {
                    return trustManager.getAcceptedIssuers();
                }
            }
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new ExpirationCheckingTrustManager() }, null);
            
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
            // ok: java-insecure-trust-manager
            // Trust manager that uses a custom keystore with specific trusted certificates
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);
            
            // Add a trusted certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream certStream = new FileInputStream("trusted-cert.pem");
            X509Certificate trustedCert = (X509Certificate) cf.generateCertificate(certStream);
            trustStore.setCertificateEntry("trusted-cert", trustedCert);
            
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

    public void good_case_13() {
        try {
            // ok: java-insecure-trust-manager
            // Trust manager that uses the system default but restricts to specific TLS versions
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(null, tmf.getTrustManagers(), null);
            
            // Create a socket factory that only allows TLS 1.2 and 1.3
            SSLSocketFactory sf = new SSLSocketFactory() {
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
                    SSLSocket socket = (SSLSocket) delegate.createSocket(s, host, port, autoClose);
                    socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
                    return socket;
                }
                
                @Override
                public Socket createSocket(String host, int port) throws IOException {
                    SSLSocket socket = (SSLSocket) delegate.createSocket(host, port);
                    socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
                    return socket;
                }
                
                @Override
                public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
                    SSLSocket socket = (SSLSocket) delegate.createSocket(host, port, localHost, localPort);
                    socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
                    return socket;
                }
                
                @Override
                public Socket createSocket(InetAddress host, int port) throws IOException {
                    SSLSocket socket = (SSLSocket) delegate.createSocket(host, port);
                    socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
                    return socket;
                }
                
                @Override
                public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
                    SSLSocket socket = (SSLSocket) delegate.createSocket(address, port, localAddress, localPort);
                    socket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
                    return socket;
                }
            };
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sf);
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            // ok: java-insecure-trust-manager
            // Trust manager that uses certificate transparency verification
            class CTVerifyingTrustManager implements X509TrustManager {
                private final X509TrustManager trustManager;
                
                public CTVerifyingTrustManager() throws Exception {
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init((KeyStore) null);
                    trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
                }
                
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    trustManager.checkClientTrusted(chain, authType);
                }
                
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    trustManager.checkServerTrusted(chain, authType);
                    
                    // Check for SCT (Signed Certificate Timestamp) in certificate extensions
                    if (chain != null && chain.length > 0) {
                        X509Certificate cert = chain[0];
                        byte[] sctExtension = cert.getExtensionValue("1.3.6.1.4.1.11129.2.4.2");
                        
                        if (sctExtension == null) {
                            throw new CertificateException("Certificate Transparency: No SCT found in certificate");
                        }
                        
                        // In a real implementation, we would verify the SCT signature here
                        System.out.println("Certificate has SCT extension");
                    }
                }
                
                public X509Certificate[] getAcceptedIssuers() {
                    return trustManager.getAcceptedIssuers();
                }
            }
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new CTVerifyingTrustManager() }, null);
            
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
            // ok: java-insecure-trust-manager
            // Trust manager that uses OCSP stapling verification
            class OCSPStaplingTrustManager implements X509TrustManager {
                private final X509TrustManager trustManager;
                
                public OCSPStaplingTrustManager() throws Exception {
                    // Enable OCSP stapling
                    System.setProperty("jdk.tls.client.enableStatusRequestExtension", "true");
                    
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init((KeyStore) null);
                    trustManager = (X509TrustManager) tmf.getTrustManagers()[0];
                }
                
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    trustManager.checkClientTrusted(chain, authType);
                }
                
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    trustManager.checkServerTrusted(chain, authType);
                    
                    // In a real implementation, we would verify the OCSP response
                    // This is typically handled by the JDK when OCSP stapling is enabled
                    System.out.println("Certificate validated with OCSP stapling enabled");
                }
                
                public X509Certificate[] getAcceptedIssuers() {
                    return trustManager.getAcceptedIssuers();
                }
            }
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { new OCSPStaplingTrustManager() }, null);
            
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}