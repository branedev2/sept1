import java.net.URL
import java.net.URI
import okhttp3.OkHttpClient
import okhttp3.Request
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.net.HttpURLConnection
import java.net.URLConnection
import kotlin.concurrent.thread
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.MalformedURLException
import okhttp3.HttpUrl
import android.net.Uri
import java.util.Properties
import java.io.FileInputStream

// True Positives (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_1() {
    // Creating a URL with HTTP protocol
    // ruleid: kotlin-url-instantiated
    val url = URL("http://example.com/api/data")
    val connection = url.openConnection() as HttpURLConnection
    connection.requestMethod = "GET"
    val response = connection.inputStream.bufferedReader().use { it.readText() }
    println("Received data: $response")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_2() {
    // Using HTTP in a string that's converted to URL
    val apiEndpoint = "http://api.example.org/users"
    // ruleid: kotlin-url-instantiated
    val url = URL(apiEndpoint)
    val connection = url.openConnection()
    val data = BufferedReader(InputStreamReader(connection.getInputStream())).readText()
    println("User data: $data")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_3() {
    // Using OkHttp with HTTP URL
    val client = OkHttpClient()
    // ruleid: kotlin-url-instantiated
    val request = Request.Builder()
        .url("http://example.com/api/sensitive-data")
        .build()
    val response = client.newCall(request).execute()
    println("Response: ${response.body?.string()}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_4() {
    // Using Retrofit with HTTP base URL
    // ruleid: kotlin-url-instantiated
    val retrofit = Retrofit.Builder()
        .baseUrl("http://api.example.com/")
        .addConverterFactory(GsonConverterFactory.create())
        .build()
    
    // API service would be defined here
    println("Retrofit client created with insecure URL")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_5() {
    // Creating URL from URI with HTTP
    val uri = URI("http", "example.com", "/path", "query=value", null)
    // ruleid: kotlin-url-instantiated
    val url = uri.toURL()
    val connection = url.openConnection()
    println("Connected to ${url.host}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_6() {
    // HTTP URL with port specified
    // ruleid: kotlin-url-instantiated
    val url = URL("http", "api.example.com", 8080, "/data")
    val connection = url.openConnection()
    println("Connected to ${url.host}:${url.port}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_7() {
    // Using HTTP URL in a background thread
    thread {
        try {
            // ruleid: kotlin-url-instantiated
            val url = URL("http://example.com/background-task")
            val connection = url.openConnection() as HttpURLConnection
            val response = connection.inputStream.bufferedReader().use { it.readText() }
            println("Background task completed: $response")
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_8() {
    // Using HTTP URL with query parameters
    val baseUrl = "http://api.example.com/search"
    val query = "kotlin+security"
    // ruleid: kotlin-url-instantiated
    val url = URL("$baseUrl?q=$query")
    val connection = url.openConnection() as HttpURLConnection
    val response = connection.inputStream.bufferedReader().use { it.readText() }
    println("Search results: $response")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_9() {
    // Using OkHttp's HttpUrl with HTTP
    // ruleid: kotlin-url-instantiated
    val httpUrl = HttpUrl.parse("http://example.org/api")
    val client = OkHttpClient()
    val request = Request.Builder()
        .url(httpUrl!!)
        .build()
    println("Request created for ${request.url}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_10() {
    // Using Android's Uri with HTTP
    // ruleid: kotlin-url-instantiated
    val uri = Uri.parse("http://example.com/android-api")
    // Converting to URL for network operations
    val url = URL(uri.toString())
    println("Android URI converted to URL: ${url.toString()}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_11() {
    // Loading configuration with HTTP URL
    val properties = Properties()
    properties.setProperty("api.endpoint", "http://config.example.com/settings")
    // ruleid: kotlin-url-instantiated
    val url = URL(properties.getProperty("api.endpoint"))
    val connection = url.openConnection()
    println("Connected to config endpoint: ${url.host}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_12() {
    // Constructing URL with string concatenation
    val protocol = "http"
    val domain = "example.com"
    val path = "/api/v2/data"
    // ruleid: kotlin-url-instantiated
    val url = URL("$protocol://$domain$path")
    val connection = url.openConnection()
    println("Connected using constructed URL: $url")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_13() {
    // Using HTTP URL in a try-catch block
    try {
        // ruleid: kotlin-url-instantiated
        val url = URL("http://api.example.com/data")
        val connection = url.openConnection() as HttpURLConnection
        connection.connectTimeout = 5000
        connection.readTimeout = 5000
        val response = connection.inputStream.bufferedReader().use { it.readText() }
        println("Response: $response")
    } catch (e: Exception) {
        println("Error connecting to URL: ${e.message}")
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_14() {
    // Using HTTP URL with authentication info
    val username = "user"
    val password = "password"
    // ruleid: kotlin-url-instantiated
    val url = URL("http://$username:$password@example.com/secure-api")
    val connection = url.openConnection()
    println("Connected with authentication to ${url.host}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
fun bad_case_15() {
    // Reading URL from external source and using it without checking protocol
    val configFile = "config.properties"
    val props = Properties()
    props.load(FileInputStream(configFile))
    val apiUrl = props.getProperty("api.url", "http://default.example.com/api")
    // ruleid: kotlin-url-instantiated
    val url = URL(apiUrl)
    val connection = url.openConnection()
    println("Connected to URL from config: ${url.toString()}")
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_1() {
    // Using HTTPS instead of HTTP
    // ok: kotlin-url-instantiated
    val url = URL("https://example.com/api/data")
    val connection = url.openConnection() as HttpURLConnection
    connection.requestMethod = "GET"
    val response = connection.inputStream.bufferedReader().use { it.readText() }
    println("Received data: $response")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_2() {
    // Using HTTPS in a string that's converted to URL
    val apiEndpoint = "https://api.example.org/users"
    // ok: kotlin-url-instantiated
    val url = URL(apiEndpoint)
    val connection = url.openConnection()
    val data = BufferedReader(InputStreamReader(connection.getInputStream())).readText()
    println("User data: $data")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_3() {
    // Using OkHttp with HTTPS URL
    val client = OkHttpClient()
    // ok: kotlin-url-instantiated
    val request = Request.Builder()
        .url("https://example.com/api/sensitive-data")
        .build()
    val response = client.newCall(request).execute()
    println("Response: ${response.body?.string()}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_4() {
    // Using Retrofit with HTTPS base URL
    // ok: kotlin-url-instantiated
    val retrofit = Retrofit.Builder()
        .baseUrl("https://api.example.com/")
        .addConverterFactory(GsonConverterFactory.create())
        .build()
    
    // API service would be defined here
    println("Retrofit client created with secure URL")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_5() {
    // Creating URL from URI with HTTPS
    val uri = URI("https", "example.com", "/path", "query=value", null)
    // ok: kotlin-url-instantiated
    val url = uri.toURL()
    val connection = url.openConnection()
    println("Connected to ${url.host}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_6() {
    // HTTPS URL with port specified
    // ok: kotlin-url-instantiated
    val url = URL("https", "api.example.com", 443, "/data")
    val connection = url.openConnection()
    println("Connected to ${url.host}:${url.port}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_7() {
    // Using HTTPS URL in a background thread
    thread {
        try {
            // ok: kotlin-url-instantiated
            val url = URL("https://example.com/background-task")
            val connection = url.openConnection() as HttpURLConnection
            val response = connection.inputStream.bufferedReader().use { it.readText() }
            println("Background task completed: $response")
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_8() {
    // Using HTTPS URL with query parameters
    val baseUrl = "https://api.example.com/search"
    val query = "kotlin+security"
    // ok: kotlin-url-instantiated
    val url = URL("$baseUrl?q=$query")
    val connection = url.openConnection() as HttpURLConnection
    val response = connection.inputStream.bufferedReader().use { it.readText() }
    println("Search results: $response")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_9() {
    // Using OkHttp's HttpUrl with HTTPS
    // ok: kotlin-url-instantiated
    val httpsUrl = HttpUrl.parse("https://example.org/api")
    val client = OkHttpClient()
    val request = Request.Builder()
        .url(httpsUrl!!)
        .build()
    println("Request created for ${request.url}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_10() {
    // Using Android's Uri with HTTPS
    // ok: kotlin-url-instantiated
    val uri = Uri.parse("https://example.com/android-api")
    // Converting to URL for network operations
    val url = URL(uri.toString())
    println("Android URI converted to URL: ${url.toString()}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_11() {
    // Loading configuration with HTTPS URL
    val properties = Properties()
    properties.setProperty("api.endpoint", "https://config.example.com/settings")
    // ok: kotlin-url-instantiated
    val url = URL(properties.getProperty("api.endpoint"))
    val connection = url.openConnection()
    println("Connected to config endpoint: ${url.host}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_12() {
    // Using file URL (not HTTP)
    // ok: kotlin-url-instantiated
    val url = URL("file:///path/to/local/file.txt")
    val connection = url.openConnection()
    val content = connection.getInputStream().bufferedReader().use { it.readText() }
    println("File content: $content")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_13() {
    // Using URL with custom protocol (not HTTP)
    // ok: kotlin-url-instantiated
    val url = URL("ftp://ftp.example.com/public/file.txt")
    val connection = url.openConnection()
    println("Connected to FTP server: ${url.host}")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_14() {
    // Enforcing HTTPS by checking and modifying URL if needed
    var urlString = "http://example.com/api"
    if (urlString.startsWith("http://")) {
        urlString = urlString.replace("http://", "https://")
    }
    // ok: kotlin-url-instantiated
    val url = URL(urlString)
    val connection = url.openConnection()
    println("Connected using secure URL: $url")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
fun good_case_15() {
    // Using a URL builder pattern to ensure HTTPS
    val protocol = "https"
    val domain = "example.com"
    val path = "/api/v2/data"
    // ok: kotlin-url-instantiated
    val url = URL("$protocol://$domain$path")
    val connection = url.openConnection()
    println("Connected using constructed secure URL: $url")
}
// {/fact}