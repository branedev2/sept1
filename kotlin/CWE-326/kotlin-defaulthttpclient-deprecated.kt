import org.apache.http.client.HttpClient
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.impl.client.SystemDefaultHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.StringEntity
import org.apache.http.util.EntityUtils
import org.apache.http.client.config.RequestConfig
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.ssl.SSLContexts
import java.io.IOException
import java.security.KeyManagementException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.net.URI
import javax.net.ssl.SSLContext

// True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_1() {
    try {
        // ruleid: kotlin-defaulthttpclient-deprecated
        val httpClient = DefaultHttpClient()
        val httpGet = HttpGet("https://api.example.com/data")
        val response = httpClient.execute(httpGet)
        val entity = response.entity
        val content = EntityUtils.toString(entity)
        println("Response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_2() {
    // ruleid: kotlin-defaulthttpclient-deprecated
    val client = DefaultHttpClient()
    try {
        val post = HttpPost("https://api.example.com/submit")
        post.entity = StringEntity("{\"name\":\"John\",\"age\":30}")
        post.setHeader("Content-Type", "application/json")
        val response = client.execute(post)
        println("Status code: ${response.statusLine.statusCode}")
    } catch (e: IOException) {
        e.printStackTrace()
    } finally {
        client.connectionManager.shutdown()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_3() {
    // Creating a custom configuration but still using DefaultHttpClient
    val params = org.apache.http.params.BasicHttpParams()
    org.apache.http.params.HttpConnectionParams.setConnectionTimeout(params, 5000)
    org.apache.http.params.HttpConnectionParams.setSoTimeout(params, 5000)
    
    // ruleid: kotlin-defaulthttpclient-deprecated
    val httpClient = DefaultHttpClient(params)
    
    try {
        val httpGet = HttpGet("https://api.example.com/users")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("User data: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_4() {
    // Using DefaultHttpClient in a more complex scenario with authentication
    // ruleid: kotlin-defaulthttpclient-deprecated
    val httpClient = DefaultHttpClient()
    val credentials = org.apache.http.auth.UsernamePasswordCredentials("user", "password")
    val authScope = org.apache.http.auth.AuthScope("api.example.com", 443)
    httpClient.credentialsProvider.setCredentials(authScope, credentials)
    
    try {
        val httpGet = HttpGet("https://api.example.com/secure-data")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("Secure data: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_5() {
    // Using DefaultHttpClient with proxy settings
    // ruleid: kotlin-defaulthttpclient-deprecated
    val httpClient = DefaultHttpClient()
    val proxy = org.apache.http.HttpHost("proxy.example.com", 8080)
    httpClient.params.setParameter(org.apache.http.conn.params.ConnRoutePNames.DEFAULT_PROXY, proxy)
    
    try {
        val httpGet = HttpGet("https://api.example.com/data")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("Data via proxy: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_6() {
    // Using DefaultHttpClient with custom retry handler
    val retryHandler = object : org.apache.http.client.HttpRequestRetryHandler {
        override fun retryRequest(exception: IOException, executionCount: Int, context: org.apache.http.protocol.HttpContext): Boolean {
            return executionCount < 3
        }
    }
    
    // ruleid: kotlin-defaulthttpclient-deprecated
    val httpClient = DefaultHttpClient()
    httpClient.setHttpRequestRetryHandler(retryHandler)
    
    try {
        val httpGet = HttpGet("https://api.example.com/unreliable-endpoint")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("Response with retry: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_7() {
    // Using DefaultHttpClient in a function that processes API data
    // ruleid: kotlin-defaulthttpclient-deprecated
    val httpClient = DefaultHttpClient()
    
    try {
        val httpGet = HttpGet("https://api.example.com/weather?city=London")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        
        // Process weather data
        val weatherData = parseWeatherData(content)
        println("Temperature: ${weatherData.temperature}°C")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

data class WeatherData(val temperature: Double)

fun parseWeatherData(json: String): WeatherData {
    // Simplified parsing logic
    return WeatherData(20.5)
}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_8() {
    // Using DefaultHttpClient with connection pooling
    val connManager = org.apache.http.impl.conn.PoolingClientConnectionManager()
    connManager.maxTotal = 100
    connManager.defaultMaxPerRoute = 20
    
    // ruleid: kotlin-defaulthttpclient-deprecated
    val httpClient = DefaultHttpClient(connManager)
    
    try {
        val httpGet = HttpGet("https://api.example.com/high-traffic-endpoint")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("High traffic response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_9() {
    // Using DefaultHttpClient with cookie management
    // ruleid: kotlin-defaulthttpclient-deprecated
    val httpClient = DefaultHttpClient()
    val cookieStore = org.apache.http.impl.client.BasicCookieStore()
    val localContext = org.apache.http.protocol.BasicHttpContext()
    localContext.setAttribute(org.apache.http.client.protocol.ClientContext.COOKIE_STORE, cookieStore)
    
    try {
        val httpGet = HttpGet("https://api.example.com/session-based")
        val response = httpClient.execute(httpGet, localContext)
        val content = EntityUtils.toString(response.entity)
        println("Session response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_10() {
    // Using DefaultHttpClient with custom request interceptor
    val requestInterceptor = object : org.apache.http.HttpRequestInterceptor {
        override fun process(request: org.apache.http.HttpRequest, context: org.apache.http.protocol.HttpContext) {
            request.addHeader("X-Custom-Header", "CustomValue")
        }
    }
    
    // ruleid: kotlin-defaulthttpclient-deprecated
    val httpClient = DefaultHttpClient()
    httpClient.addRequestInterceptor(requestInterceptor)
    
    try {
        val httpGet = HttpGet("https://api.example.com/custom-header-endpoint")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("Custom header response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_11() {
    // Using DefaultHttpClient with custom response handler
    // ruleid: kotlin-defaulthttpclient-deprecated
    val httpClient = DefaultHttpClient()
    
    try {
        val httpGet = HttpGet("https://api.example.com/data")
        val responseHandler = org.apache.http.client.ResponseHandler<String> { response ->
            val status = response.statusLine.statusCode
            if (status >= 200 && status < 300) {
                EntityUtils.toString(response.entity)
            } else {
                throw org.apache.http.client.ClientProtocolException("Unexpected response status: $status")
            }
        }
        
        val content = httpClient.execute(httpGet, responseHandler)
        println("Response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_12() {
    // Using DefaultHttpClient in a class constructor
    class ApiClient(private val baseUrl: String) {
        // ruleid: kotlin-defaulthttpclient-deprecated
        private val httpClient = DefaultHttpClient()
        
        fun fetchData(endpoint: String): String {
            try {
                val httpGet = HttpGet("$baseUrl/$endpoint")
                val response = httpClient.execute(httpGet)
                return EntityUtils.toString(response.entity)
            } catch (e: Exception) {
                e.printStackTrace()
                return ""
            }
        }
    }
    
    val client = ApiClient("https://api.example.com")
    val data = client.fetchData("users")
    println("User data: $data")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_13() {
    // Using DefaultHttpClient with timeout settings
    val params = org.apache.http.params.BasicHttpParams()
    org.apache.http.params.HttpConnectionParams.setConnectionTimeout(params, 3000)
    org.apache.http.params.HttpConnectionParams.setSoTimeout(params, 5000)
    
    // ruleid: kotlin-defaulthttpclient-deprecated
    val httpClient = DefaultHttpClient(params)
    
    try {
        val httpGet = HttpGet("https://api.example.com/slow-endpoint")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("Response from slow endpoint: $content")
    } catch (e: Exception) {
        println("Request timed out or failed: ${e.message}")
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_14() {
    // Using DefaultHttpClient with multipart entity
    // ruleid: kotlin-defaulthttpclient-deprecated
    val httpClient = DefaultHttpClient()
    
    try {
        val httpPost = HttpPost("https://api.example.com/upload")
        val multipartEntity = org.apache.http.entity.mime.MultipartEntity()
        
        // Add text part
        multipartEntity.addPart("description", org.apache.http.entity.mime.content.StringBody("File description"))
        
        // Add file part (simplified)
        val file = java.io.File("example.txt")
        multipartEntity.addPart("file", org.apache.http.entity.mime.content.FileBody(file))
        
        httpPost.entity = multipartEntity
        val response = httpClient.execute(httpPost)
        val content = EntityUtils.toString(response.entity)
        println("Upload response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_15() {
    // Using DefaultHttpClient with custom SSL context (insecure)
    try {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, org.apache.http.conn.ssl.TrustSelfSignedStrategy().trustManager, null)
        
        val sslSocketFactory = SSLConnectionSocketFactory(sslContext)
        val schemeRegistry = org.apache.http.conn.scheme.SchemeRegistry()
        schemeRegistry.register(org.apache.http.conn.scheme.Scheme("https", 443, org.apache.http.conn.ssl.SSLSocketFactory(sslContext)))
        
        val connectionManager = org.apache.http.impl.conn.SingleClientConnManager(schemeRegistry)
        
        // ruleid: kotlin-defaulthttpclient-deprecated
        val httpClient = DefaultHttpClient(connectionManager)
        
        val httpGet = HttpGet("https://self-signed.example.com/data")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("SSL response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_1() {
    try {
        // ok: kotlin-defaulthttpclient-deprecated
        val httpClient = SystemDefaultHttpClient()
        val httpGet = HttpGet("https://api.example.com/data")
        val response = httpClient.execute(httpGet)
        val entity = response.entity
        val content = EntityUtils.toString(entity)
        println("Response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_2() {
    // ok: kotlin-defaulthttpclient-deprecated
    val httpClient = HttpClients.createDefault()
    try {
        val post = HttpPost("https://api.example.com/submit")
        post.entity = StringEntity("{\"name\":\"John\",\"age\":30}")
        post.setHeader("Content-Type", "application/json")
        val response = httpClient.execute(post)
        println("Status code: ${response.statusLine.statusCode}")
    } catch (e: IOException) {
        e.printStackTrace()
    } finally {
        httpClient.close()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_3() {
    // ok: kotlin-defaulthttpclient-deprecated
    val requestConfig = RequestConfig.custom()
        .setConnectTimeout(5000)
        .setSocketTimeout(5000)
        .build()
    
    val httpClient = HttpClients.custom()
        .setDefaultRequestConfig(requestConfig)
        .build()
    
    try {
        val httpGet = HttpGet("https://api.example.com/users")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("User data: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        httpClient.close()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_4() {
    // ok: kotlin-defaulthttpclient-deprecated
    val credentialsProvider = org.apache.http.impl.client.BasicCredentialsProvider()
    val credentials = org.apache.http.auth.UsernamePasswordCredentials("user", "password")
    val authScope = org.apache.http.auth.AuthScope("api.example.com", 443)
    credentialsProvider.setCredentials(authScope, credentials)
    
    val httpClient = HttpClients.custom()
        .setDefaultCredentialsProvider(credentialsProvider)
        .build()
    
    try {
        val httpGet = HttpGet("https://api.example.com/secure-data")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("Secure data: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        httpClient.close()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_5() {
    // ok: kotlin-defaulthttpclient-deprecated
    val proxy = org.apache.http.HttpHost("proxy.example.com", 8080)
    val httpClient = HttpClients.custom()
        .setProxy(proxy)
        .build()
    
    try {
        val httpGet = HttpGet("https://api.example.com/data")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("Data via proxy: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        httpClient.close()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_6() {
    // ok: kotlin-defaulthttpclient-deprecated
    val retryHandler = org.apache.http.impl.client.DefaultHttpRequestRetryHandler(3, true)
    val httpClient = HttpClients.custom()
        .setRetryHandler(retryHandler)
        .build()
    
    try {
        val httpGet = HttpGet("https://api.example.com/unreliable-endpoint")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("Response with retry: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        httpClient.close()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_7() {
    // ok: kotlin-defaulthttpclient-deprecated
    val httpClient = HttpClients.createDefault()
    
    try {
        val httpGet = HttpGet("https://api.example.com/weather?city=London")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        
        // Process weather data
        val weatherData = parseWeatherData(content)
        println("Temperature: ${weatherData.temperature}°C")
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        httpClient.close()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_8() {
    // ok: kotlin-defaulthttpclient-deprecated
    val connectionManager = org.apache.http.impl.conn.PoolingHttpClientConnectionManager()
    connectionManager.maxTotal = 100
    connectionManager.defaultMaxPerRoute = 20
    
    val httpClient = HttpClients.custom()
        .setConnectionManager(connectionManager)
        .build()
    
    try {
        val httpGet = HttpGet("https://api.example.com/high-traffic-endpoint")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("High traffic response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_9() {
    // ok: kotlin-defaulthttpclient-deprecated
    val cookieStore = org.apache.http.impl.client.BasicCookieStore()
    val httpClient = HttpClients.custom()
        .setDefaultCookieStore(cookieStore)
        .build()
    
    try {
        val httpGet = HttpGet("https://api.example.com/session-based")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("Session response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        httpClient.close()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_10() {
    // ok: kotlin-defaulthttpclient-deprecated
    val httpClient = HttpClients.custom()
        .addInterceptorFirst { request, context ->
            request.addHeader("X-Custom-Header", "CustomValue")
        }
        .build()
    
    try {
        val httpGet = HttpGet("https://api.example.com/custom-header-endpoint")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("Custom header response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        httpClient.close()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_11() {
    // ok: kotlin-defaulthttpclient-deprecated
    val httpClient = HttpClients.createDefault()
    
    try {
        val httpGet = HttpGet("https://api.example.com/data")
        val responseHandler = org.apache.http.client.ResponseHandler<String> { response ->
            val status = response.statusLine.statusCode
            if (status >= 200 && status < 300) {
                EntityUtils.toString(response.entity)
            } else {
                throw org.apache.http.client.ClientProtocolException("Unexpected response status: $status")
            }
        }
        
        val content = httpClient.execute(httpGet, responseHandler)
        println("Response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        httpClient.close()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_12() {
    // ok: kotlin-defaulthttpclient-deprecated
    class ApiClient(private val baseUrl: String) {
        private val httpClient = HttpClients.createDefault()
        
        fun fetchData(endpoint: String): String {
            try {
                val httpGet = HttpGet("$baseUrl/$endpoint")
                val response = httpClient.execute(httpGet)
                return EntityUtils.toString(response.entity)
            } catch (e: Exception) {
                e.printStackTrace()
                return ""
            } finally {
                // In a real implementation, we'd manage the client lifecycle properly
            }
        }
        
        fun close() {
            httpClient.close()
        }
    }
    
    val client = ApiClient("https://api.example.com")
    val data = client.fetchData("users")
    println("User data: $data")
    client.close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_13() {
    // ok: kotlin-defaulthttpclient-deprecated
    val requestConfig = RequestConfig.custom()
        .setConnectTimeout(3000)
        .setSocketTimeout(5000)
        .build()
    
    val httpClient = HttpClients.custom()
        .setDefaultRequestConfig(requestConfig)
        .build()
    
    try {
        val httpGet = HttpGet("https://api.example.com/slow-endpoint")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("Response from slow endpoint: $content")
    } catch (e: Exception) {
        println("Request timed out or failed: ${e.message}")
    } finally {
        httpClient.close()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_14() {
    // ok: kotlin-defaulthttpclient-deprecated
    val httpClient = HttpClients.createDefault()
    
    try {
        val httpPost = HttpPost("https://api.example.com/upload")
        val multipartEntityBuilder = org.apache.http.entity.mime.MultipartEntityBuilder.create()
        
        // Add text part
        multipartEntityBuilder.addTextBody("description", "File description")
        
        // Add file part
        val file = java.io.File("example.txt")
        multipartEntityBuilder.addBinaryBody("file", file)
        
        httpPost.entity = multipartEntityBuilder.build()
        val response = httpClient.execute(httpPost)
        val content = EntityUtils.toString(response.entity)
        println("Upload response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        httpClient.close()
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_15() {
    // ok: kotlin-defaulthttpclient-deprecated
    try {
        val sslContext = SSLContexts.custom()
            .loadTrustMaterial(null, TrustSelfSignedStrategy())
            .build()
        
        val sslSocketFactory = SSLConnectionSocketFactory(sslContext)
        
        val httpClient = HttpClients.custom()
            .setSSLSocketFactory(sslSocketFactory)
            .build()
        
        val httpGet = HttpGet("https://self-signed.example.com/data")
        val response = httpClient.execute(httpGet)
        val content = EntityUtils.toString(response.entity)
        println("SSL response: $content")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
// {/fact}