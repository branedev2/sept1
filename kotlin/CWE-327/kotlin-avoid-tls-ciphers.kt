import java.security.KeyStore
import javax.net.ssl.*
import okhttp3.OkHttpClient
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import java.net.URL
import java.net.HttpURLConnection
import javax.net.ssl.HttpsURLConnection
import okhttp3.ConnectionSpec
import okhttp3.TlsVersion
import java.util.Arrays
import java.util.concurrent.TimeUnit
import io.ktor.network.tls.*
import io.ktor.network.tls.extensions.*
import io.ktor.network.sockets.*
import io.ktor.util.*
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.features.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import kotlinx.coroutines.*

// True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_1() {
    val sslContext = SSLContext.getInstance("TLS")
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    sslContext.init(null, trustManagerFactory.trustManagers, SecureRandom())
    
    val sslSocketFactory = sslContext.socketFactory
    
    // ruleid: kotlin-avoid-tls-ciphers
    val enabledCipherSuites = arrayOf(
        "TLS_RSA_WITH_NULL_SHA256",  // Anonymous cipher suite
        "SSL_RSA_WITH_DES_CBC_SHA"   // Weak cipher
    )
    
    val connection = URL("https://example.com").openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sslSocketFactory
    connection.setEnabledCipherSuites(enabledCipherSuites)
    connection.connect()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_2() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    // ruleid: kotlin-avoid-tls-ciphers
    val cipherSuites = arrayOf(
        "TLS_DH_anon_WITH_AES_128_CBC_SHA",  // Anonymous cipher suite
        "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" // Anonymous cipher suite
    )
    
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        .connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .cipherSuites(*cipherSuites)
            .build()))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_3() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    // ruleid: kotlin-avoid-tls-ciphers
    val weakCiphers = arrayOf(
        "SSL_RSA_EXPORT_WITH_RC4_40_MD5",  // Export-grade cipher
        "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA" // Export-grade cipher
    )
    
    val sslSocketFactory = sslContext.socketFactory
    val socket = sslSocketFactory.createSocket("example.com", 443) as SSLSocket
    socket.enabledCipherSuites = weakCiphers
    socket.startHandshake()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_4() {
    // ruleid: kotlin-avoid-tls-ciphers
    val insecureCiphers = arrayOf(
        "TLS_RSA_WITH_RC4_128_SHA",  // RC4 is considered broken
        "TLS_RSA_WITH_RC4_128_MD5"   // RC4 with MD5 is even worse
    )
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, SecureRandom())
    
    val engine = SSLEngine()
    engine.enabledCipherSuites = insecureCiphers
    engine.useClientMode = true
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_5() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    // ruleid: kotlin-avoid-tls-ciphers
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        .connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .cipherSuites("TLS_ECDH_anon_WITH_AES_256_CBC_SHA")
            .build()))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_6() {
    // ruleid: kotlin-avoid-tls-ciphers
    val weakCiphers = arrayOf(
        "TLS_RSA_WITH_NULL_MD5",  // NULL encryption
        "TLS_RSA_WITH_NULL_SHA"   // NULL encryption
    )
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    val sslSocketFactory = sslContext.socketFactory
    val socket = sslSocketFactory.createSocket() as SSLSocket
    socket.enabledCipherSuites = weakCiphers
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_7() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    // ruleid: kotlin-avoid-tls-ciphers
    val connectionSpec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        .cipherSuites(
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",  // 3DES is considered weak
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"  // 3DES is considered weak
        )
        .build()
    
    val client = OkHttpClient.Builder()
        .connectionSpecs(listOf(connectionSpec))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_8() {
    // ruleid: kotlin-avoid-tls-ciphers
    val insecureCiphers = arrayOf(
        "TLS_DHE_DSS_WITH_DES_CBC_SHA",  // DES is weak
        "SSL_DHE_DSS_WITH_DES_CBC_SHA"   // SSL with DES is weak
    )
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    val connection = URL("https://example.com").openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sslContext.socketFactory
    connection.setEnabledCipherSuites(insecureCiphers)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_9() {
    runBlocking {
        // ruleid: kotlin-avoid-tls-ciphers
        val client = HttpClient(OkHttp) {
            engine {
                config {
                    connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                        .cipherSuites("TLS_ECDH_anon_WITH_AES_128_CBC_SHA256")
                        .build()))
                }
            }
        }
        
        val response = client.get<String>("https://example.com")
        println(response)
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_10() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    // ruleid: kotlin-avoid-tls-ciphers
    val socket = sslContext.socketFactory.createSocket("example.com", 443) as SSLSocket
    val weakCiphers = arrayOf(
        "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",  // Export-grade cipher
        "TLS_RSA_EXPORT_WITH_RC4_40_MD5"       // Export-grade cipher
    )
    socket.enabledCipherSuites = weakCiphers
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_11() {
    // ruleid: kotlin-avoid-tls-ciphers
    val insecureCiphers = arrayOf(
        "TLS_KRB5_WITH_DES_CBC_SHA",      // DES is weak
        "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"  // 3DES is considered weak
    )
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    val sslEngine = sslContext.createSSLEngine()
    sslEngine.enabledCipherSuites = insecureCiphers
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_12() {
    // ruleid: kotlin-avoid-tls-ciphers
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        .connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .cipherSuites("TLS_RSA_WITH_SEED_CBC_SHA")  // SEED cipher is not recommended
            .build()))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_13() {
    // ruleid: kotlin-avoid-tls-ciphers
    val weakCiphers = arrayOf(
        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",  // RC4 is broken
        "TLS_ECDHE_RSA_WITH_RC4_128_SHA"     // RC4 is broken
    )
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    val connection = URL("https://example.com").openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sslContext.socketFactory
    connection.setEnabledCipherSuites(weakCiphers)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_14() {
    // ruleid: kotlin-avoid-tls-ciphers
    val insecureCiphers = arrayOf(
        "TLS_PSK_WITH_NULL_SHA",  // NULL encryption
        "TLS_PSK_WITH_RC4_128_SHA" // RC4 is broken
    )
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    val sslEngine = sslContext.createSSLEngine()
    sslEngine.enabledCipherSuites = insecureCiphers
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_15() {
    runBlocking {
        // ruleid: kotlin-avoid-tls-ciphers
        val client = HttpClient(CIO) {
            engine {
                https {
                    cipherSuites = listOf(
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,  // Not forward secret
                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA   // Not forward secret
                    )
                }
            }
        }
        
        val response = client.get<String>("https://example.com")
        println(response)
    }
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_1() {
    val sslContext = SSLContext.getInstance("TLS")
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    sslContext.init(null, trustManagerFactory.trustManagers, SecureRandom())
    
    val sslSocketFactory = sslContext.socketFactory
    
    // ok: kotlin-avoid-tls-ciphers
    val enabledCipherSuites = arrayOf(
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    )
    
    val connection = URL("https://example.com").openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sslSocketFactory
    connection.setEnabledCipherSuites(enabledCipherSuites)
    connection.connect()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_2() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    // ok: kotlin-avoid-tls-ciphers
    val cipherSuites = arrayOf(
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    )
    
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        .connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .cipherSuites(*cipherSuites)
            .build()))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_3() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    // ok: kotlin-avoid-tls-ciphers
    val secureCiphers = arrayOf(
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    )
    
    val sslSocketFactory = sslContext.socketFactory
    val socket = sslSocketFactory.createSocket("example.com", 443) as SSLSocket
    socket.enabledCipherSuites = secureCiphers
    socket.startHandshake()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_4() {
    // ok: kotlin-avoid-tls-ciphers
    val secureCiphers = arrayOf(
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
    )
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, SecureRandom())
    
    val engine = SSLEngine()
    engine.enabledCipherSuites = secureCiphers
    engine.useClientMode = true
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_5() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    // ok: kotlin-avoid-tls-ciphers
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        .connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .cipherSuites("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384")
            .build()))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_6() {
    // ok: kotlin-avoid-tls-ciphers
    val secureCiphers = arrayOf(
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    )
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    val sslSocketFactory = sslContext.socketFactory
    val socket = sslSocketFactory.createSocket() as SSLSocket
    socket.enabledCipherSuites = secureCiphers
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_7() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    // ok: kotlin-avoid-tls-ciphers
    val connectionSpec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        .cipherSuites(
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        )
        .build()
    
    val client = OkHttpClient.Builder()
        .connectionSpecs(listOf(connectionSpec))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_8() {
    // ok: kotlin-avoid-tls-ciphers
    val secureCiphers = arrayOf(
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
    )
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    val connection = URL("https://example.com").openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sslContext.socketFactory
    connection.setEnabledCipherSuites(secureCiphers)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_9() {
    runBlocking {
        // ok: kotlin-avoid-tls-ciphers
        val client = HttpClient(OkHttp) {
            engine {
                config {
                    connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                        .cipherSuites("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
                        .build()))
                }
            }
        }
        
        val response = client.get<String>("https://example.com")
        println(response)
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_10() {
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    // ok: kotlin-avoid-tls-ciphers
    val socket = sslContext.socketFactory.createSocket("example.com", 443) as SSLSocket
    val secureCiphers = arrayOf(
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
    )
    socket.enabledCipherSuites = secureCiphers
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_11() {
    // ok: kotlin-avoid-tls-ciphers
    val secureCiphers = arrayOf(
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    )
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    val sslEngine = sslContext.createSSLEngine()
    sslEngine.enabledCipherSuites = secureCiphers
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_12() {
    // ok: kotlin-avoid-tls-ciphers
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        .connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .cipherSuites("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
            .build()))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_13() {
    // ok: kotlin-avoid-tls-ciphers
    val secureCiphers = arrayOf(
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
    )
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    val connection = URL("https://example.com").openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sslContext.socketFactory
    connection.setEnabledCipherSuites(secureCiphers)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_14() {
    // ok: kotlin-avoid-tls-ciphers
    val secureCiphers = arrayOf(
        "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"
    )
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    
    val sslEngine = sslContext.createSSLEngine()
    sslEngine.enabledCipherSuites = secureCiphers
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_15() {
    runBlocking {
        // ok: kotlin-avoid-tls-ciphers
        val client = HttpClient(CIO) {
            engine {
                https {
                    cipherSuites = listOf(
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                    )
                }
            }
        }
        
        val response = client.get<String>("https://example.com")
        println(response)
    }
}
// {/fact}