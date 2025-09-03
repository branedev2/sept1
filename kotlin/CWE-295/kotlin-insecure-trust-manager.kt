import java.io.IOException
import java.net.URL
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.*
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

// True Positive Examples (Vulnerable Code)

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_1() {
    // Creating a trust manager that does not validate certificate chains
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        // ruleid: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            // Empty implementation - accepts any client certificate
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            // Empty implementation - accepts any server certificate
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return arrayOf()
        }
    })

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustAllCerts, java.security.SecureRandom())
    val sslSocketFactory = sslContext.socketFactory

    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory, trustAllCerts[0] as X509TrustManager)
        .hostnameVerifier { _, _ -> true }
        .build()
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_2() {
    // Another variation with empty implementation
    val naiveTrustManager = object : X509TrustManager {
        // ruleid: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            // No validation
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            // No validation
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return emptyArray()
        }
    }

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(naiveTrustManager), null)
    HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.socketFactory)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_3() {
    // Using anonymous class with empty implementation
    val sc = SSLContext.getInstance("SSL")
    sc.init(null, arrayOf<TrustManager>(object : X509TrustManager {
        // ruleid: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}

        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }), java.security.SecureRandom())

    val connection = URL("https://example.com").openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sc.socketFactory
    connection.connect()
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_4() {
    // Trust manager with empty implementation in Retrofit client
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        // ruleid: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            // Do nothing, trust any client
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            // Do nothing, trust any server
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return arrayOf()
        }
    })

    val sslContext = SSLContext.getInstance("SSL")
    sslContext.init(null, trustAllCerts, java.security.SecureRandom())

    val okHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustAllCerts[0] as X509TrustManager)
        .build()

    val retrofit = Retrofit.Builder()
        .baseUrl("https://api.example.com/")
        .client(okHttpClient)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_5() {
    // Trust manager with comments explaining the insecure behavior
    val unsafeTrustManager = object : X509TrustManager {
        // ruleid: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            // Intentionally empty for testing purposes
            // WARNING: This accepts any client certificate
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            // Intentionally empty for testing purposes
            // WARNING: This accepts any server certificate
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return emptyArray()
        }
    }

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(unsafeTrustManager), java.security.SecureRandom())
    HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.socketFactory)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_6() {
    // Trust manager with empty implementation and hostname verifier that accepts all
    val trustManager = object : X509TrustManager {
        // ruleid: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}

        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(trustManager), java.security.SecureRandom())

    val hostnameVerifier = HostnameVerifier { _, _ -> true }

    val connection = URL("https://example.com").openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sslContext.socketFactory
    connection.hostnameVerifier = hostnameVerifier
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_7() {
    // Trust manager with empty implementation in a class
    class InsecureTrustManager : X509TrustManager {
        // ruleid: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            // No validation
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            // No validation
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return emptyArray()
        }
    }

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(InsecureTrustManager()), java.security.SecureRandom())
    HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.socketFactory)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_8() {
    // Trust manager with empty implementation and try-catch block
    val trustManager = object : X509TrustManager {
        // ruleid: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            try {
                // Empty implementation
            } catch (e: Exception) {
                // Ignore exceptions
            }
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            try {
                // Empty implementation
            } catch (e: Exception) {
                // Ignore exceptions
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return emptyArray()
        }
    }

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(trustManager), java.security.SecureRandom())
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_9() {
    // Trust manager with empty implementation and logging
    val trustManager = object : X509TrustManager {
        // ruleid: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            println("Warning: Skipping client certificate validation")
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            println("Warning: Skipping server certificate validation")
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return emptyArray()
        }
    }

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(trustManager), java.security.SecureRandom())
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_10() {
    // Trust manager with empty implementation in a factory
    class InsecureTrustManagerFactory : TrustManagerFactory("InsecureTrustManagerFactory", null, null) {
        override fun engineInit(keyStore: KeyStore?) {}
        override fun engineInit(managerFactoryParameters: ManagerFactoryParameters?) {}
        
        override fun engineGetTrustManagers(): Array<TrustManager> {
            return arrayOf(object : X509TrustManager {
                // ruleid: kotlin-insecure-trust-manager
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            })
        }
    }

    val factory = InsecureTrustManagerFactory()
    val trustManagers = factory.engineGetTrustManagers()
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustManagers, java.security.SecureRandom())
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_11() {
    // Trust manager with empty implementation and conditional logic
    val trustManager = object : X509TrustManager {
        // ruleid: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            if (System.getProperty("dev.mode") == "true") {
                // Skip validation in dev mode
            } else {
                // Still empty implementation in production
            }
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            if (System.getProperty("dev.mode") == "true") {
                // Skip validation in dev mode
            } else {
                // Still empty implementation in production
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return emptyArray()
        }
    }

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(trustManager), java.security.SecureRandom())
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_12() {
    // Trust manager with empty implementation in a companion object
    class NetworkUtils {
        companion object {
            fun getInsecureTrustManager(): X509TrustManager {
                return object : X509TrustManager {
                    // ruleid: kotlin-insecure-trust-manager
                    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                        // Empty implementation
                    }

                    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                        // Empty implementation
                    }

                    override fun getAcceptedIssuers(): Array<X509Certificate> {
                        return emptyArray()
                    }
                }
            }
        }
    }

    val trustManager = NetworkUtils.getInsecureTrustManager()
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(trustManager), java.security.SecureRandom())
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_13() {
    // Trust manager with empty implementation and lambda expressions
    val checkCertificate: (Array<X509Certificate>, String) -> Unit = { _, _ -> }
    
    val trustManager = object : X509TrustManager {
        // ruleid: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            checkCertificate(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            checkCertificate(chain, authType)
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return emptyArray()
        }
    }

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(trustManager), java.security.SecureRandom())
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_14() {
    // Trust manager with empty implementation in a higher-order function
    fun createTrustManager(): X509TrustManager {
        return object : X509TrustManager {
            // ruleid: kotlin-insecure-trust-manager
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                // Empty implementation
            }

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                // Empty implementation
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                return emptyArray()
            }
        }
    }

    val trustManager = createTrustManager()
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(trustManager), java.security.SecureRandom())
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
fun bad_case_15() {
    // Trust manager with empty implementation and extension function
    fun X509TrustManager.logCertificateCheck() {
        println("Certificate check called but not implemented")
    }
    
    val trustManager = object : X509TrustManager {
        // ruleid: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            logCertificateCheck()
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            logCertificateCheck()
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return emptyArray()
        }
    }

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(trustManager), java.security.SecureRandom())
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_1() {
    // Using default trust manager from system
    // ok: kotlin-insecure-trust-manager
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    val trustManagers = trustManagerFactory.trustManagers
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustManagers, null)
    HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.socketFactory)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_2() {
    // Using custom KeyStore for trust manager
    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
    keyStore.load(null)
    
    // Add your trusted certificates to the keyStore here
    
    // ok: kotlin-insecure-trust-manager
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(keyStore)
    val trustManagers = trustManagerFactory.trustManagers
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustManagers, null)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_3() {
    // Proper implementation that throws exceptions for untrusted certificates
    val trustManager = object : X509TrustManager {
        // ok: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            if (chain.isEmpty()) {
                throw CertificateException("Certificate chain is empty")
            }
            // Perform actual certificate validation
            for (cert in chain) {
                cert.checkValidity()
                // Additional validation logic here
            }
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            if (chain.isEmpty()) {
                throw CertificateException("Certificate chain is empty")
            }
            // Perform actual certificate validation
            for (cert in chain) {
                cert.checkValidity()
                // Additional validation logic here
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            // Return actual trusted issuers
            return arrayOf()
        }
    }

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(trustManager), java.security.SecureRandom())
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_4() {
    // Using system default trust manager with OkHttp
    // ok: kotlin-insecure-trust-manager
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustManagerFactory.trustManagers, java.security.SecureRandom())
    
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustManagerFactory.trustManagers[0] as X509TrustManager)
        .build()
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_5() {
    // Loading certificates from a file and using them in a trust manager
    val keyStoreFile = java.io.FileInputStream("keystore.jks")
    val keyStorePassword = "password".toCharArray()
    
    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
    keyStore.load(keyStoreFile, keyStorePassword)
    
    // ok: kotlin-insecure-trust-manager
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(keyStore)
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustManagerFactory.trustManagers, null)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_6() {
    // Using a custom trust manager that delegates to the default one
    val defaultTrustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    defaultTrustManagerFactory.init(null as KeyStore?)
    val defaultTrustManager = defaultTrustManagerFactory.trustManagers[0] as X509TrustManager
    
    val customTrustManager = object : X509TrustManager {
        // ok: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            defaultTrustManager.checkClientTrusted(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            defaultTrustManager.checkServerTrusted(chain, authType)
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return defaultTrustManager.acceptedIssuers
        }
    }
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(customTrustManager), null)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_7() {
    // Using a trust manager with certificate pinning
    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
    keyStore.load(null)
    
    // Add pinned certificates to keyStore
    
    // ok: kotlin-insecure-trust-manager
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(keyStore)
    
    val pinnedTrustManager = object : X509TrustManager {
        private val delegate = trustManagerFactory.trustManagers[0] as X509TrustManager
        
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            delegate.checkClientTrusted(chain, authType)
            // Additional pinning validation
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            delegate.checkServerTrusted(chain, authType)
            // Verify certificate public key matches pinned hash
            val cert = chain[0]
            val publicKey = cert.publicKey.encoded
            val publicKeyHash = java.security.MessageDigest.getInstance("SHA-256").digest(publicKey)
            // Compare with pinned hash
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return delegate.acceptedIssuers
        }
    }
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(pinnedTrustManager), null)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_8() {
    // Using a trust manager with certificate revocation checking
    // ok: kotlin-insecure-trust-manager
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    val defaultTrustManager = trustManagerFactory.trustManagers[0] as X509TrustManager
    
    val revocationCheckingTrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            defaultTrustManager.checkClientTrusted(chain, authType)
            checkRevocationStatus(chain)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            defaultTrustManager.checkServerTrusted(chain, authType)
            checkRevocationStatus(chain)
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return defaultTrustManager.acceptedIssuers
        }
        
        private fun checkRevocationStatus(chain: Array<X509Certificate>) {
            for (cert in chain) {
                // Check OCSP or CRL status
                val certStatus = cert.getExtensionValue("2.5.29.31") // CRL Distribution Points
                // Perform actual revocation check
            }
        }
    }
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(revocationCheckingTrustManager), null)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_9() {
    // Using a trust manager with custom validation logic
    // ok: kotlin-insecure-trust-manager
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    val defaultTrustManager = trustManagerFactory.trustManagers[0] as X509TrustManager
    
    val customValidationTrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            defaultTrustManager.checkClientTrusted(chain, authType)
            validateCertificateChain(chain)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            defaultTrustManager.checkServerTrusted(chain, authType)
            validateCertificateChain(chain)
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return defaultTrustManager.acceptedIssuers
        }
        
        private fun validateCertificateChain(chain: Array<X509Certificate>) {
            // Custom validation logic
            for (cert in chain) {
                // Check certificate attributes
                val subject = cert.subjectX500Principal.name
                if (!subject.contains("O=Trusted Organization")) {
                    throw CertificateException("Certificate not from trusted organization")
                }
            }
        }
    }
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(customValidationTrustManager), null)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_10() {
    // Using a trust manager with environment-specific validation
    val isProduction = System.getProperty("env") == "production"
    
    // ok: kotlin-insecure-trust-manager
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    val defaultTrustManager = trustManagerFactory.trustManagers[0] as X509TrustManager
    
    val environmentAwareTrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            defaultTrustManager.checkClientTrusted(chain, authType)
            if (isProduction) {
                // Additional strict validation for production
                validateStrictly(chain)
            }
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            defaultTrustManager.checkServerTrusted(chain, authType)
            if (isProduction) {
                // Additional strict validation for production
                validateStrictly(chain)
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return defaultTrustManager.acceptedIssuers
        }
        
        private fun validateStrictly(chain: Array<X509Certificate>) {
            // Additional validation for production environment
            for (cert in chain) {
                // Check certificate strength, expiration, etc.
                val validityPeriod = cert.notAfter.time - cert.notBefore.time
                val maxValidityMs = 365L * 24 * 60 * 60 * 1000 // 1 year
                if (validityPeriod > maxValidityMs) {
                    throw CertificateException("Certificate validity period too long")
                }
            }
        }
    }
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(environmentAwareTrustManager), null)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_11() {
    // Using a trust manager with logging but proper validation
    // ok: kotlin-insecure-trust-manager
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    val defaultTrustManager = trustManagerFactory.trustManagers[0] as X509TrustManager
    
    val loggingTrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            println("Validating client certificate: ${chain[0].subjectX500Principal}")
            defaultTrustManager.checkClientTrusted(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            println("Validating server certificate: ${chain[0].subjectX500Principal}")
            defaultTrustManager.checkServerTrusted(chain, authType)
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return defaultTrustManager.acceptedIssuers
        }
    }
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(loggingTrustManager), null)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_12() {
    // Using a trust manager factory in a utility class
    class SecureNetworkUtils {
        companion object {
            fun createSecureTrustManager(): X509TrustManager {
                // ok: kotlin-insecure-trust-manager
                val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                trustManagerFactory.init(null as KeyStore?)
                return trustManagerFactory.trustManagers[0] as X509TrustManager
            }
        }
    }
    
    val trustManager = SecureNetworkUtils.createSecureTrustManager()
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(trustManager), null)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_13() {
    // Using a trust manager with proper error handling
    // ok: kotlin-insecure-trust-manager
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    val defaultTrustManager = trustManagerFactory.trustManagers[0] as X509TrustManager
    
    val robustTrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            try {
                defaultTrustManager.checkClientTrusted(chain, authType)
            } catch (e: CertificateException) {
                println("Certificate validation failed: ${e.message}")
                throw e
            }
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            try {
                defaultTrustManager.checkServerTrusted(chain, authType)
            } catch (e: CertificateException) {
                println("Certificate validation failed: ${e.message}")
                throw e
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return defaultTrustManager.acceptedIssuers
        }
    }
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(robustTrustManager), null)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_14() {
    // Using a trust manager with certificate transparency validation
    // ok: kotlin-insecure-trust-manager
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    val defaultTrustManager = trustManagerFactory.trustManagers[0] as X509TrustManager
    
    val ctTrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            defaultTrustManager.checkClientTrusted(chain, authType)
            checkCertificateTransparency(chain)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            defaultTrustManager.checkServerTrusted(chain, authType)
            checkCertificateTransparency(chain)
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return defaultTrustManager.acceptedIssuers
        }
        
        private fun checkCertificateTransparency(chain: Array<X509Certificate>) {
            // Check for SCT (Signed Certificate Timestamp) in certificate
            for (cert in chain) {
                val sctExtension = cert.getExtensionValue("1.3.6.1.4.1.11129.2.4.2")
                if (sctExtension == null) {
                    throw CertificateException("Certificate transparency validation failed: No SCT found")
                }
                // Validate SCT
            }
        }
    }
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(ctTrustManager), null)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
fun good_case_15() {
    // Using a trust manager with proper validation and caching
    class CachingTrustManager(private val delegate: X509TrustManager) : X509TrustManager {
        private val validatedServerCerts = mutableMapOf<String, Long>()
        
        // ok: kotlin-insecure-trust-manager
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            delegate.checkClientTrusted(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            val certHash = chain[0].signature.contentHashCode().toString()
            val now = System.currentTimeMillis()
            val cachedTime = validatedServerCerts[certHash]
            
            if (cachedTime == null || now - cachedTime > 3600000) { // 1 hour cache
                delegate.checkServerTrusted(chain, authType)
                validatedServerCerts[certHash] = now
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return delegate.acceptedIssuers
        }
    }
    
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    val defaultTrustManager = trustManagerFactory.trustManagers[0] as X509TrustManager
    
    val cachingTrustManager = CachingTrustManager(defaultTrustManager)
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(cachingTrustManager), null)
}
// {/fact}