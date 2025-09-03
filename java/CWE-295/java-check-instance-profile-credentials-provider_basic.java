import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.auth.SystemPropertiesCredentialsProvider;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.ClientConfiguration;

public class InstanceProfileCredentialsProviderExamples {

    // BAD CASES - Vulnerable implementations

// {fact rule=improper-certificate-validation@v1.0 defects=1}
    public void bad_case_1() {
        // Creating an insecure trust manager that accepts all certificates
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
        
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());
            
            // ruleid: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = new InstanceProfileCredentialsProvider();
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .withClientConfiguration(new ClientConfiguration().withSocketFactory(sc.getSocketFactory()))
                .build();
            
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // Creating a trust manager that doesn't validate certificate chains
            TrustManager[] trustAllCertificates = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCertificates, new SecureRandom());
            
            // ruleid: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider credentialsProvider = new InstanceProfileCredentialsProvider(false);
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withClientConfiguration(new ClientConfiguration().withSocketFactory(sslContext.getSocketFactory()))
                .build();
            
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            // Creating an all-trusting trust manager
            X509TrustManager trustManager = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    // Skip validation
                }
                
                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    // Skip validation
                }
                
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { trustManager }, null);
            
            // ruleid: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = InstanceProfileCredentialsProvider.getInstance();
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setSocketFactory(sslContext.getSocketFactory());
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .withClientConfiguration(clientConfig)
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            // Trust manager that accepts all certificates
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
            // ruleid: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider credentialsProvider = 
                new InstanceProfileCredentialsProvider();
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] insecureTrustManager = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, insecureTrustManager, new SecureRandom());
            
            // ruleid: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = 
                InstanceProfileCredentialsProvider.createAsyncRefreshingProvider(true);
            
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setSocketFactory(sc.getSocketFactory());
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .withClientConfiguration(clientConfig)
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            // Custom trust manager that accepts all certificates
            X509TrustManager customTrustManager = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) { }
                
                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) { }
                
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { customTrustManager }, null);
            SSLSocketFactory factory = sslContext.getSocketFactory();
            
            // ruleid: java-check-instance-profile-credentials-provider
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new InstanceProfileCredentialsProvider())
                .withClientConfiguration(new ClientConfiguration().withSocketFactory(factory))
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            // Trust all certificates
            TrustManager[] trustAllCertificates = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCertificates, new SecureRandom());
            
            // ruleid: java-check-instance-profile-credentials-provider
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setSocketFactory(sslContext.getSocketFactory());
            
            InstanceProfileCredentialsProvider credentialsProvider = 
                InstanceProfileCredentialsProvider.getInstance();
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withClientConfiguration(clientConfig)
                .withRegion("us-west-2")
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            // Create a trust manager that accepts all certificates
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new SecureRandom());
            
            // ruleid: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = 
                InstanceProfileCredentialsProvider.createAsyncRefreshingProvider(false);
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .withClientConfiguration(new ClientConfiguration().withSocketFactory(sc.getSocketFactory()))
                .withRegion("us-east-1")
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        // Creating a trust manager that doesn't validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };
        
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
            // ruleid: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = new InstanceProfileCredentialsProvider(true);
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(
                    "https://s3.amazonaws.com", "us-east-1"))
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] insecureTrustManagers = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, insecureTrustManagers, new SecureRandom());
            
            // ruleid: java-check-instance-profile-credentials-provider
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setSocketFactory(sslContext.getSocketFactory());
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(InstanceProfileCredentialsProvider.getInstance())
                .withClientConfiguration(clientConfig)
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            // Create a trust manager that accepts all certificates
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // ruleid: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider credentialsProvider = 
                new InstanceProfileCredentialsProvider();
            
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setSocketFactory(sslContext.getSocketFactory());
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withClientConfiguration(clientConfig)
                .withPathStyleAccessEnabled(true)
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            // Create a trust manager that doesn't validate certificate chains
            TrustManager[] trustAllCertificates = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCertificates, new SecureRandom());
            
            // ruleid: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = 
                InstanceProfileCredentialsProvider.createAsyncRefreshingProvider(true);
            
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setSocketFactory(sc.getSocketFactory());
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .withClientConfiguration(clientConfig)
                .withRegion("eu-west-1")
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            // Create an insecure trust manager
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            // ruleid: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider credentialsProvider = 
                new InstanceProfileCredentialsProvider();
            
            ClientConfiguration clientConfiguration = new ClientConfiguration();
            clientConfiguration.setSocketFactory(sslContext.getSocketFactory());
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withClientConfiguration(clientConfiguration)
                .withForceGlobalBucketAccessEnabled(true)
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            // Create a trust manager that accepts all certificates
            TrustManager[] trustAllCertificates = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCertificates, new SecureRandom());
            
            // ruleid: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = 
                InstanceProfileCredentialsProvider.getInstance();
            
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setSocketFactory(sslContext.getSocketFactory());
            clientConfig.setConnectionTimeout(5000);
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .withClientConfiguration(clientConfig)
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            // Create a trust manager that accepts all certificates
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new SecureRandom());
            
            // ruleid: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider credentialsProvider = 
                new InstanceProfileCredentialsProvider(false);
            
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setSocketFactory(sc.getSocketFactory());
            clientConfig.setMaxConnections(100);
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withClientConfiguration(clientConfig)
                .withRegion("ap-southeast-1")
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // GOOD CASES - Secure implementations

    public void good_case_1() {
        try {
            // ok: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = new InstanceProfileCredentialsProvider();
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // ok: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider credentialsProvider = 
                InstanceProfileCredentialsProvider.getInstance();
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion("us-west-2")
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            // Using the default SSL context which validates certificates properly
            // ok: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = 
                new InstanceProfileCredentialsProvider(true);
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .withRegion("us-east-1")
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            // ok: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider credentialsProvider = 
                InstanceProfileCredentialsProvider.createAsyncRefreshingProvider(true);
            
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setConnectionTimeout(5000);
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withClientConfiguration(clientConfig)
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            // ok: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = 
                new InstanceProfileCredentialsProvider();
            
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setMaxErrorRetry(3);
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .withClientConfiguration(clientConfig)
                .withRegion("eu-central-1")
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            // ok: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider credentialsProvider = 
                InstanceProfileCredentialsProvider.getInstance();
            
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setConnectionTimeout(10000);
            clientConfig.setSocketTimeout(10000);
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withClientConfiguration(clientConfig)
                .withRegion("ap-northeast-1")
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            // ok: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = 
                new InstanceProfileCredentialsProvider(false);
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .withPathStyleAccessEnabled(true)
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            // ok: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider credentialsProvider = 
                InstanceProfileCredentialsProvider.createAsyncRefreshingProvider(false);
            
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setMaxConnections(50);
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withClientConfiguration(clientConfig)
                .withForceGlobalBucketAccessEnabled(true)
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            // ok: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = 
                InstanceProfileCredentialsProvider.getInstance();
            
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setUserAgentPrefix("CustomUserAgent");
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .withClientConfiguration(clientConfig)
                .withRegion("sa-east-1")
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            // Using environment variable credentials provider instead
            // ok: java-check-instance-profile-credentials-provider
            AWSCredentialsProvider credentialsProvider = 
                new EnvironmentVariableCredentialsProvider();
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            // Using system properties credentials provider
            // ok: java-check-instance-profile-credentials-provider
            AWSCredentialsProvider credentialsProvider = 
                new SystemPropertiesCredentialsProvider();
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion("us-west-1")
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            // Using profile credentials provider
            // ok: java-check-instance-profile-credentials-provider
            AWSCredentialsProvider credentialsProvider = 
                new ProfileCredentialsProvider();
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion("eu-west-2")
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            // Using default credentials provider chain
            // ok: java-check-instance-profile-credentials-provider
            AWSCredentialsProvider credentialsProvider = 
                DefaultAWSCredentialsProviderChain.getInstance();
            
            ClientConfiguration clientConfig = new ClientConfiguration();
            clientConfig.setProxyHost("proxy.example.com");
            clientConfig.setProxyPort(8080);
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withClientConfiguration(clientConfig)
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            // Using static credentials provider
            // ok: java-check-instance-profile-credentials-provider
            BasicAWSCredentials awsCreds = new BasicAWSCredentials(
                System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY_ID"), 
                System.getenv("AWS_SECRET_AC_REDACTED_TWILIO_ID_KEY")
            );
            
            AWSCredentialsProvider credentialsProvider = 
                new AWSStaticCredentialsProvider(awsCreds);
            
            AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(credentialsProvider)
                .withRegion("ap-south-1")
                .build();
                
            s3.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            // Using instance profile credentials provider with proper configuration
            // ok: java-check-instance-profile-credentials-provider
            InstanceProfileCredentialsProvider provider = 
                new InstanceProfileCredentialsProvider();
            
            ClientConfiguration clientConfig = new ClientConfiguration();
            // Using default SSL context which validates certificates properly
            
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(provider)
                .withClientConfiguration(clientConfig)
                .withRegion("ca-central-1")
                .build();
                
            s3Client.listBuckets();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}