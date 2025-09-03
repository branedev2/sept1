import java.security.KeyStore
import javax.net.ssl.*
import okhttp3.OkHttpClient
import java.net.URL
import java.net.HttpURLConnection
import java.io.IOException
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import java.security.SecureRandom
import java.security.cert.X509Certificate
import okhttp3.ConnectionSpec
import okhttp3.TlsVersion
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import com.google.gson.GsonBuilder
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.impl.client.HttpClients
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.client.methods.HttpGet
import org.apache.http.util.EntityUtils
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.ssl.SSLContextBuilder

// True Positive Examples (Insecure TLS/SSL Versions)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_1() {
    // Creating SSLContext with insecure TLSv1.0
    val sslContext = SSLContext.getInstance("TLSv1")
    // ruleid: kotlin-insecure-tls-version
    sslContext.init(null, null, SecureRandom())
    
    val sslSocketFactory = sslContext.socketFactory
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory, TrustAllCerts())
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_2() {
    // Creating SSLContext with insecure SSLv3
    // ruleid: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("SSLv3")
    sslContext.init(null, null, SecureRandom())
    
    val url = URL("https://example.com")
    val connection = url.openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sslContext.socketFactory
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_3() {
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    
    // Using TLSv1.1 which is insecure
    // ruleid: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLSv1.1")
    sslContext.init(null, trustManagerFactory.trustManagers, SecureRandom())
    
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustManagerFactory.trustManagers[0] as X509TrustManager)
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_4() {
    // OkHttp client with explicit TLSv1.0 specification
    val spec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        // ruleid: kotlin-insecure-tls-version
        .tlsVersions(TlsVersion.TLS_1_0)
        .build()
    
    val client = OkHttpClient.Builder()
        .connectionSpecs(listOf(spec))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_5() {
    // Using multiple TLS versions including insecure ones
    val spec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        // ruleid: kotlin-insecure-tls-version
        .tlsVersions(TlsVersion.TLS_1_0, TlsVersion.TLS_1_1, TlsVersion.TLS_1_2)
        .build()
    
    val client = OkHttpClient.Builder()
        .connectionSpecs(listOf(spec))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_6() {
    // Apache HttpClient with SSLv3
    // ruleid: kotlin-insecure-tls-version
    val sslContext = SSLContextBuilder()
        .useProtocol("SSLv3")
        .loadTrustMaterial(null, TrustSelfSignedStrategy())
        .build()
    
    val sslsf = SSLConnectionSocketFactory(sslContext)
    val httpClient = HttpClients.custom()
        .setSSLSocketFactory(sslsf)
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_7() {
    // Creating custom socket factory with TLSv1.0
    // ruleid: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLSv1")
    sslContext.init(null, arrayOf<TrustManager>(TrustAllCerts()), SecureRandom())
    
    val factory = object : SSLSocketFactory() {
        private val internalSocketFactory = sslContext.socketFactory
        
        override fun getDefaultCipherSuites(): Array<String> = internalSocketFactory.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = internalSocketFactory.supportedCipherSuites
        override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket = internalSocketFactory.createSocket(s, host, port, autoClose)
        override fun createSocket(host: String, port: Int): Socket = internalSocketFactory.createSocket(host, port)
        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket = internalSocketFactory.createSocket(host, port, localHost, localPort)
        override fun createSocket(host: InetAddress, port: Int): Socket = internalSocketFactory.createSocket(host, port)
        override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket = internalSocketFactory.createSocket(address, port, localAddress, localPort)
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_8() {
    // Using SSLContext with TLSv1.1 for Retrofit
    // ruleid: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLSv1.1")
    sslContext.init(null, null, SecureRandom())
    
    val sslSocketFactory = sslContext.socketFactory
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory, TrustAllCerts())
        .build()
    
    val retrofit = Retrofit.Builder()
        .baseUrl("https://api.example.com/")
        .client(client)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_9() {
    // Setting explicit protocols with SSLv3
    val protocols = arrayOf("SSLv3", "TLSv1")
    
    // ruleid: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, SecureRandom())
    
    val sslSocketFactory = sslContext.socketFactory
    val socket = sslSocketFactory.createSocket() as SSLSocket
    socket.enabledProtocols = protocols
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_10() {
    // Using HttpsURLConnection with TLSv1.0
    val url = URL("https://example.com")
    val connection = url.openConnection() as HttpsURLConnection
    
    // ruleid: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLSv1")
    sslContext.init(null, null, SecureRandom())
    
    connection.sslSocketFactory = sslContext.socketFactory
    connection.connect()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_11() {
    // Using multiple protocols including insecure ones
    // ruleid: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, SecureRandom())
    
    val sslSocketFactory = sslContext.socketFactory
    val socket = sslSocketFactory.createSocket() as SSLSocket
    socket.enabledProtocols = arrayOf("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_12() {
    // Creating SSLContext with TLSv1.0 and custom trust manager
    val trustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
    
    // ruleid: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLSv1")
    sslContext.init(null, arrayOf(trustManager), SecureRandom())
    
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustManager)
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_13() {
    // Apache HttpClient with TLSv1.1
    // ruleid: kotlin-insecure-tls-version
    val sslContext = SSLContextBuilder()
        .useProtocol("TLSv1.1")
        .loadTrustMaterial(null, TrustSelfSignedStrategy())
        .build()
    
    val sslsf = SSLConnectionSocketFactory(sslContext)
    val httpClient = HttpClients.custom()
        .setSSLSocketFactory(sslsf)
        .build()
    
    val httpGet = HttpGet("https://example.com")
    val response = httpClient.execute(httpGet)
    val entity = response.entity
    val content = EntityUtils.toString(entity)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_14() {
    // OkHttp client with multiple TLS versions including insecure ones
    val spec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        // ruleid: kotlin-insecure-tls-version
        .tlsVersions(TlsVersion.TLS_1_1, TlsVersion.TLS_1_2)
        .build()
    
    val client = OkHttpClient.Builder()
        .connectionSpecs(listOf(spec))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_15() {
    // Using SSLContext with explicit protocol selection of SSLv3
    // ruleid: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("SSLv3")
    sslContext.init(null, null, SecureRandom())
    
    val url = URL("https://example.com")
    val connection = url.openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sslContext.socketFactory
    
    try {
        val inputStream = connection.inputStream
        // Process the input stream
    } catch (e: IOException) {
        e.printStackTrace()
    } finally {
        connection.disconnect()
    }
}
// {/fact}

// True Negative Examples (Secure TLS/SSL Versions)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_1() {
    // Creating SSLContext with secure TLSv1.2
    val sslContext = SSLContext.getInstance("TLSv1.2")
    // ok: kotlin-insecure-tls-version
    sslContext.init(null, null, SecureRandom())
    
    val sslSocketFactory = sslContext.socketFactory
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory, TrustAllCerts())
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_2() {
    // Creating SSLContext with secure TLSv1.3
    // ok: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLSv1.3")
    sslContext.init(null, null, SecureRandom())
    
    val url = URL("https://example.com")
    val connection = url.openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sslContext.socketFactory
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_3() {
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(null as KeyStore?)
    
    // Using TLSv1.2 which is secure
    // ok: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLSv1.2")
    sslContext.init(null, trustManagerFactory.trustManagers, SecureRandom())
    
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustManagerFactory.trustManagers[0] as X509TrustManager)
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_4() {
    // OkHttp client with explicit TLSv1.2 specification
    val spec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        // ok: kotlin-insecure-tls-version
        .tlsVersions(TlsVersion.TLS_1_2)
        .build()
    
    val client = OkHttpClient.Builder()
        .connectionSpecs(listOf(spec))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_5() {
    // Using multiple secure TLS versions
    val spec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        // ok: kotlin-insecure-tls-version
        .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)
        .build()
    
    val client = OkHttpClient.Builder()
        .connectionSpecs(listOf(spec))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_6() {
    // Apache HttpClient with TLSv1.2
    // ok: kotlin-insecure-tls-version
    val sslContext = SSLContextBuilder()
        .useProtocol("TLSv1.2")
        .loadTrustMaterial(null, TrustSelfSignedStrategy())
        .build()
    
    val sslsf = SSLConnectionSocketFactory(sslContext)
    val httpClient = HttpClients.custom()
        .setSSLSocketFactory(sslsf)
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_7() {
    // Creating custom socket factory with TLSv1.2
    // ok: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLSv1.2")
    sslContext.init(null, arrayOf<TrustManager>(TrustAllCerts()), SecureRandom())
    
    val factory = object : SSLSocketFactory() {
        private val internalSocketFactory = sslContext.socketFactory
        
        override fun getDefaultCipherSuites(): Array<String> = internalSocketFactory.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = internalSocketFactory.supportedCipherSuites
        override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket = internalSocketFactory.createSocket(s, host, port, autoClose)
        override fun createSocket(host: String, port: Int): Socket = internalSocketFactory.createSocket(host, port)
        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket = internalSocketFactory.createSocket(host, port, localHost, localPort)
        override fun createSocket(host: InetAddress, port: Int): Socket = internalSocketFactory.createSocket(host, port)
        override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket = internalSocketFactory.createSocket(address, port, localAddress, localPort)
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_8() {
    // Using SSLContext with TLSv1.3 for Retrofit
    // ok: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLSv1.3")
    sslContext.init(null, null, SecureRandom())
    
    val sslSocketFactory = sslContext.socketFactory
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory, TrustAllCerts())
        .build()
    
    val retrofit = Retrofit.Builder()
        .baseUrl("https://api.example.com/")
        .client(client)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_9() {
    // Setting explicit protocols with only secure versions
    val protocols = arrayOf("TLSv1.2", "TLSv1.3")
    
    // ok: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, SecureRandom())
    
    val sslSocketFactory = sslContext.socketFactory
    val socket = sslSocketFactory.createSocket() as SSLSocket
    socket.enabledProtocols = protocols
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_10() {
    // Using HttpsURLConnection with TLSv1.2
    val url = URL("https://example.com")
    val connection = url.openConnection() as HttpsURLConnection
    
    // ok: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLSv1.2")
    sslContext.init(null, null, SecureRandom())
    
    connection.sslSocketFactory = sslContext.socketFactory
    connection.connect()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_11() {
    // Using default TLS context which typically uses the highest available secure version
    // ok: kotlin-insecure-tls-version
    val sslContext = SSLContext.getDefault()
    
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, TrustAllCerts())
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_12() {
    // Creating SSLContext with TLSv1.2 and custom trust manager
    val trustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
    
    // ok: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLSv1.2")
    sslContext.init(null, arrayOf(trustManager), SecureRandom())
    
    val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustManager)
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_13() {
    // Apache HttpClient with TLSv1.3
    // ok: kotlin-insecure-tls-version
    val sslContext = SSLContextBuilder()
        .useProtocol("TLSv1.3")
        .loadTrustMaterial(null, TrustSelfSignedStrategy())
        .build()
    
    val sslsf = SSLConnectionSocketFactory(sslContext)
    val httpClient = HttpClients.custom()
        .setSSLSocketFactory(sslsf)
        .build()
    
    val httpGet = HttpGet("https://example.com")
    val response = httpClient.execute(httpGet)
    val entity = response.entity
    val content = EntityUtils.toString(entity)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_14() {
    // Using ConnectionSpec.MODERN_TLS which defaults to secure TLS versions
    // ok: kotlin-insecure-tls-version
    val client = OkHttpClient.Builder()
        .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS))
        .build()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_15() {
    // Using the latest TLS version available with explicit protocol
    // ok: kotlin-insecure-tls-version
    val sslContext = SSLContext.getInstance("TLSv1.3")
    sslContext.init(null, null, SecureRandom())
    
    val url = URL("https://example.com")
    val connection = url.openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sslContext.socketFactory
    
    try {
        val inputStream = connection.inputStream
        // Process the input stream
    } catch (e: IOException) {
        e.printStackTrace()
    } finally {
        connection.disconnect()
    }
}
// {/fact}

// Helper class for the examples
private class TrustAllCerts : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}