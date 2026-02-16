import java.net.URL
import java.net.HttpURLConnection
import java.net.URI
import java.io.BufferedReader
import java.io.InputStreamReader
import org.springframework.web.bind.annotation.*
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.ResponseEntity
import org.springframework.web.client.RestTemplate
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils
import javax.servlet.http.HttpServletRequest
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.owasp.esapi.ESAPI
import java.net.MalformedURLException
import java.util.regex.Pattern
import kotlin.io.path.Path
import java.nio.file.Files

// True Positive Examples (Vulnerable Code)

// {fact rule=server-side-request-forgery@v1.0 defects=1}
@RestController
fun bad_case_1(@RequestParam url: String) {
    val urlConnection = URL(url).openConnection() as HttpURLConnection
    // ruleid: kotlin-server-side-request-forgery
    val response = urlConnection.inputStream.bufferedReader().use { it.readText() }
    println(response)
}
// {/fact}

@RestController
@RequestMapping("/api")
class BadController1 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @GetMapping("/fetch")
    fun bad_case_2(@RequestParam url: String): String {
        val restTemplate = RestTemplate()
        // ruleid: kotlin-server-side-request-forgery
        val response = restTemplate.getForObject(url, String::class.java)
        return response ?: "No response"
    }
// {/fact}
}

@RestController
class BadController2 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @PostMapping("/proxy")
    fun bad_case_3(@RequestBody requestBody: Map<String, String>): String {
        val url = requestBody["url"] ?: throw IllegalArgumentException("URL is required")
        val client = OkHttpClient()
        val request = Request.Builder()
            .url(url)
            .build()
        
        // ruleid: kotlin-server-side-request-forgery
        val response = client.newCall(request).execute()
        return response.body?.string() ?: "No response"
    }
// {/fact}
}

@Controller
class BadController3 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @GetMapping("/fetch-content")
    fun bad_case_4(request: HttpServletRequest): String {
        val url = request.getParameter("url")
        val httpClient = HttpClients.createDefault()
        val httpGet = HttpGet(url)
        
        // ruleid: kotlin-server-side-request-forgery
        val response = httpClient.execute(httpGet)
        val entity = response.entity
        return EntityUtils.toString(entity)
    }
// {/fact}
}

@RestController
class BadController4 {
    @GetMapping("/fetch-headers")
    fun bad_case_5(@RequestHeader("Target-URL") targetUrl: String): String {
        val connection = URL(targetUrl).openConnection() as HttpURLConnection
        connection.requestMethod = "GET"
        
        // ruleid: kotlin-server-side-request-forgery
        val responseCode = connection.responseCode
        val response = connection.inputStream.bufferedReader().use { it.readText() }
        return "Response Code: $responseCode, Body: $response"
    }
}

@RestController
class BadController5 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @GetMapping("/exchange")
    fun bad_case_6(@RequestParam url: String): String {
        val restTemplate = RestTemplate()
        val headers = HttpHeaders()
        val entity = HttpEntity<String>(headers)
        
        // ruleid: kotlin-server-side-request-forgery
        val response: ResponseEntity<String> = restTemplate.exchange(
            url,
            HttpMethod.GET,
            entity,
            String::class.java
        )
        return response.body ?: "No response"
    }
// {/fact}
}

@RestController
class BadController6 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @GetMapping("/fetch-with-path")
    fun bad_case_7(@RequestParam path: String): String {
        val baseUrl = "https://api.example.com"
        val fullUrl = "$baseUrl$path"
        val client = OkHttpClient()
        val request = Request.Builder()
            .url(fullUrl)
            .build()
        
        // ruleid: kotlin-server-side-request-forgery
        val response = client.newCall(request).execute()
        return response.body?.string() ?: "No response"
    }
// {/fact}
}

@RestController
class BadController7 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @GetMapping("/redirect")
    fun bad_case_8(@RequestParam redirectUrl: String): String {
        val httpClient = HttpClients.createDefault()
        val httpGet = HttpGet(redirectUrl)
        httpGet.addHeader("User-Agent", "Mozilla/5.0")
        
        // ruleid: kotlin-server-side-request-forgery
        val response = httpClient.execute(httpGet)
        val entity = response.entity
        return EntityUtils.toString(entity)
    }
// {/fact}
}

@RestController
class BadController8 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @GetMapping("/complex-fetch")
    fun bad_case_9(request: HttpServletRequest): String {
        val protocol = request.getParameter("protocol") ?: "https"
        val host = request.getParameter("host") ?: "example.com"
        val path = request.getParameter("path") ?: "/"
        val port = request.getParameter("port")?.toIntOrNull() ?: 443
        
        val urlString = "$protocol://$host:$port$path"
        val url = URL(urlString)
        val connection = url.openConnection() as HttpURLConnection
        
        // ruleid: kotlin-server-side-request-forgery
        val response = connection.inputStream.bufferedReader().use { it.readText() }
        return response
    }
// {/fact}
}

@RestController
class BadController9 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @PostMapping("/dynamic-service")
    fun bad_case_10(@RequestBody requestBody: Map<String, Any>): String {
        val serviceUrl = requestBody["serviceUrl"] as? String ?: throw IllegalArgumentException("Service URL is required")
        val restTemplate = RestTemplate()
        
        // ruleid: kotlin-server-side-request-forgery
        val response = restTemplate.postForObject(serviceUrl, requestBody, String::class.java)
        return response ?: "No response"
    }
// {/fact}
}

@RestController
class BadController10 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @GetMapping("/fetch-resource")
    fun bad_case_11(@RequestParam resourceId: String): String {
        val resourceUrl = "https://api.example.com/resources/$resourceId"
        val client = OkHttpClient()
        val request = Request.Builder()
            .url(resourceUrl)
            .build()
        
        // ruleid: kotlin-server-side-request-forgery
        val response = client.newCall(request).execute()
        return response.body?.string() ?: "No response"
    }
// {/fact}
}

@RestController
class BadController11 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @GetMapping("/fetch-with-uri")
    fun bad_case_12(@RequestParam uriString: String): String {
        val uri = URI(uriString)
        val httpClient = HttpClients.createDefault()
        val httpGet = HttpGet(uri)
        
        // ruleid: kotlin-server-side-request-forgery
        val response = httpClient.execute(httpGet)
        val entity = response.entity
        return EntityUtils.toString(entity)
    }
// {/fact}
}

@RestController
class BadController12 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @GetMapping("/fetch-with-template")
    fun bad_case_13(@RequestParam template: String, @RequestParam id: String): String {
        val url = template.replace("{id}", id)
        val restTemplate = RestTemplate()
        
        // ruleid: kotlin-server-side-request-forgery
        val response = restTemplate.getForObject(url, String::class.java)
        return response ?: "No response"
    }
// {/fact}
}

@RestController
class BadController13 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @GetMapping("/fetch-with-query")
    fun bad_case_14(@RequestParam baseUrl: String, @RequestParam query: String): String {
        val fullUrl = if (baseUrl.contains("?")) "$baseUrl&$query" else "$baseUrl?$query"
        val client = OkHttpClient()
        val request = Request.Builder()
            .url(fullUrl)
            .build()
        
        // ruleid: kotlin-server-side-request-forgery
        val response = client.newCall(request).execute()
        return response.body?.string() ?: "No response"
    }
// {/fact}
}

@RestController
class BadController14 {
// {fact rule=server-side-request-forgery@v1.0 defects=1}
    @GetMapping("/fetch-with-fragment")
    fun bad_case_15(@RequestParam url: String, @RequestParam fragment: String): String {
        val fullUrl = "$url#$fragment"
        val connection = URL(fullUrl).openConnection() as HttpURLConnection
        
        // ruleid: kotlin-server-side-request-forgery
        val response = connection.inputStream.bufferedReader().use { it.readText() }
        return response
    }
// {/fact}
}

// True Negative Examples (Secure Code)

@RestController
class GoodController1 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @GetMapping("/safe-fetch")
    fun good_case_1(@RequestParam url: String): String {
        // Validate URL against whitelist
        val allowedDomains = listOf("api.example.com", "api.mycompany.com")
        val urlObj = URL(url)
        
        // ok: kotlin-server-side-request-forgery
        if (!allowedDomains.contains(urlObj.host)) {
            throw SecurityException("Domain not allowed")
        }
        
        val connection = urlObj.openConnection() as HttpURLConnection
        val response = connection.inputStream.bufferedReader().use { it.readText() }
        return response
    }
// {/fact}
}

@RestController
@RequestMapping("/api")
class GoodController2 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @GetMapping("/safe-template")
    fun good_case_2(@RequestParam url: String): String {
        // Canonicalize and validate URL
        val canonicalUrl = ESAPI.encoder().canonicalize(url)
        val urlPattern = Pattern.compile("^https://api\\.example\\.com/.*$")
        
        // ok: kotlin-server-side-request-forgery
        if (!urlPattern.matcher(canonicalUrl).matches()) {
            throw SecurityException("Invalid URL pattern")
        }
        
        val restTemplate = RestTemplate()
        val response = restTemplate.getForObject(canonicalUrl, String::class.java)
        return response ?: "No response"
    }
// {/fact}
}

@RestController
class GoodController3 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @PostMapping("/safe-proxy")
    fun good_case_3(@RequestBody requestBody: Map<String, String>): String {
        val url = requestBody["url"] ?: throw IllegalArgumentException("URL is required")
        
        // Use a predefined list of allowed endpoints
        val allowedEndpoints = mapOf(
            "users" to "https://api.example.com/users",
            "products" to "https://api.example.com/products",
            "orders" to "https://api.example.com/orders"
        )
        
        // ok: kotlin-server-side-request-forgery
        val endpoint = allowedEndpoints[url] ?: throw SecurityException("Endpoint not allowed")
        
        val client = OkHttpClient()
        val request = Request.Builder()
            .url(endpoint)
            .build()
        
        val response = client.newCall(request).execute()
        return response.body?.string() ?: "No response"
    }
// {/fact}
}

@Controller
class GoodController4 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @GetMapping("/safe-content")
    fun good_case_4(request: HttpServletRequest): String {
        val resourceId = request.getParameter("id")
        
        // Validate input is numeric only
        // ok: kotlin-server-side-request-forgery
        if (!resourceId.matches(Regex("^[0-9]+$"))) {
            throw IllegalArgumentException("Invalid resource ID")
        }
        
        // Use the validated ID to construct a URL to a known endpoint
        val url = "https://api.example.com/resources/$resourceId"
        
        val httpClient = HttpClients.createDefault()
        val httpGet = HttpGet(url)
        val response = httpClient.execute(httpGet)
        val entity = response.entity
        return EntityUtils.toString(entity)
    }
// {/fact}
}

@RestController
class GoodController5 {
    @GetMapping("/safe-headers")
    fun good_case_5(@RequestHeader("Target-URL") targetUrl: String): String {
        // Parse the URL and validate against an IP blacklist
        val url = URL(targetUrl)
        val host = url.host
        val ipAddress = try {
            java.net.InetAddress.getByName(host).hostAddress
        } catch (e: Exception) {
            throw SecurityException("Cannot resolve host")
        }
        
        val blacklistedIPs = listOf("127.0.0.1", "192.168.0.1", "10.0.0.1")
        
        // ok: kotlin-server-side-request-forgery
        if (blacklistedIPs.contains(ipAddress) || ipAddress.startsWith("172.16.") || ipAddress.startsWith("169.254.")) {
            throw SecurityException("Access to internal network not allowed")
        }
        
        val connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = "GET"
        val responseCode = connection.responseCode
        val response = connection.inputStream.bufferedReader().use { it.readText() }
        return "Response Code: $responseCode, Body: $response"
    }
}

@RestController
class GoodController6 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @GetMapping("/safe-exchange")
    fun good_case_6(@RequestParam endpoint: String): String {
        // Use a URL builder with a fixed base URL
        val baseUrl = "https://api.example.com"
        
        // ok: kotlin-server-side-request-forgery
        val safeUrl = when (endpoint) {
            "users" -> "$baseUrl/users"
            "products" -> "$baseUrl/products"
            "orders" -> "$baseUrl/orders"
            else -> throw IllegalArgumentException("Invalid endpoint")
        }
        
        val restTemplate = RestTemplate()
        val headers = HttpHeaders()
        val entity = HttpEntity<String>(headers)
        val response: ResponseEntity<String> = restTemplate.exchange(
            safeUrl,
            HttpMethod.GET,
            entity,
            String::class.java
        )
        return response.body ?: "No response"
    }
// {/fact}
}

@RestController
class GoodController7 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @GetMapping("/safe-path")
    fun good_case_7(@RequestParam path: String): String {
        // Validate path format
        // ok: kotlin-server-side-request-forgery
        if (!path.matches(Regex("^/[a-zA-Z0-9_/-]+$"))) {
            throw IllegalArgumentException("Invalid path format")
        }
        
        val baseUrl = "https://api.example.com"
        val fullUrl = "$baseUrl$path"
        
        val client = OkHttpClient()
        val request = Request.Builder()
            .url(fullUrl)
            .build()
        
        val response = client.newCall(request).execute()
        return response.body?.string() ?: "No response"
    }
// {/fact}
}

@RestController
class GoodController8 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @GetMapping("/safe-redirect")
    fun good_case_8(@RequestParam redirectId: String): String {
        // Use a map of allowed redirect URLs
        val redirectMap = mapOf(
            "home" to "https://example.com/home",
            "login" to "https://example.com/login",
            "dashboard" to "https://example.com/dashboard"
        )
        
        // ok: kotlin-server-side-request-forgery
        val redirectUrl = redirectMap[redirectId] ?: throw IllegalArgumentException("Invalid redirect ID")
        
        val httpClient = HttpClients.createDefault()
        val httpGet = HttpGet(redirectUrl)
        httpGet.addHeader("User-Agent", "Mozilla/5.0")
        
        val response = httpClient.execute(httpGet)
        val entity = response.entity
        return EntityUtils.toString(entity)
    }
// {/fact}
}

@RestController
class GoodController9 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @GetMapping("/safe-complex-fetch")
    fun good_case_9(request: HttpServletRequest): String {
        val host = request.getParameter("host") ?: "example.com"
        val path = request.getParameter("path") ?: "/"
        
        // Validate host against whitelist
        val allowedHosts = listOf("api.example.com", "data.example.com")
        
        // ok: kotlin-server-side-request-forgery
        if (!allowedHosts.contains(host)) {
            throw SecurityException("Host not allowed")
        }
        
        // Validate path format
        if (!path.matches(Regex("^/[a-zA-Z0-9_/-]+$"))) {
            throw IllegalArgumentException("Invalid path format")
        }
        
        val urlString = "https://$host$path"
        val url = URL(urlString)
        val connection = url.openConnection() as HttpURLConnection
        
        val response = connection.inputStream.bufferedReader().use { it.readText() }
        return response
    }
// {/fact}
}

@RestController
class GoodController10 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @PostMapping("/safe-service")
    fun good_case_10(@RequestBody requestBody: Map<String, Any>): String {
        val serviceType = requestBody["serviceType"] as? String ?: throw IllegalArgumentException("Service type is required")
        
        // Map service type to predefined URLs
        // ok: kotlin-server-side-request-forgery
        val serviceUrl = when (serviceType) {
            "users" -> "https://api.example.com/users"
            "products" -> "https://api.example.com/products"
            "orders" -> "https://api.example.com/orders"
            else -> throw IllegalArgumentException("Invalid service type")
        }
        
        val restTemplate = RestTemplate()
        val response = restTemplate.postForObject(serviceUrl, requestBody, String::class.java)
        return response ?: "No response"
    }
// {/fact}
}

@RestController
class GoodController11 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @GetMapping("/safe-resource")
    fun good_case_11(@RequestParam resourceId: String): String {
        // Validate resource ID format
        // ok: kotlin-server-side-request-forgery
        if (!resourceId.matches(Regex("^[a-zA-Z0-9_-]+$"))) {
            throw IllegalArgumentException("Invalid resource ID format")
        }
        
        val resourceUrl = "https://api.example.com/resources/$resourceId"
        val client = OkHttpClient()
        val request = Request.Builder()
            .url(resourceUrl)
            .build()
        
        val response = client.newCall(request).execute()
        return response.body?.string() ?: "No response"
    }
// {/fact}
}

@RestController
class GoodController12 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @GetMapping("/safe-uri")
    fun good_case_12(@RequestParam uriPath: String): String {
        // Validate path and construct URI with fixed base
        // ok: kotlin-server-side-request-forgery
        if (!uriPath.matches(Regex("^[a-zA-Z0-9_/-]+$"))) {
            throw IllegalArgumentException("Invalid URI path format")
        }
        
        val baseUri = "https://api.example.com"
        val uri = URI("$baseUri/$uriPath")
        
        val httpClient = HttpClients.createDefault()
        val httpGet = HttpGet(uri)
        
        val response = httpClient.execute(httpGet)
        val entity = response.entity
        return EntityUtils.toString(entity)
    }
// {/fact}
}

@RestController
class GoodController13 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @GetMapping("/safe-template")
    fun good_case_13(@RequestParam templateId: String, @RequestParam id: String): String {
        // Use a predefined set of templates
        val templates = mapOf(
            "user" to "https://api.example.com/users/{id}",
            "product" to "https://api.example.com/products/{id}",
            "order" to "https://api.example.com/orders/{id}"
        )
        
        // ok: kotlin-server-side-request-forgery
        val template = templates[templateId] ?: throw IllegalArgumentException("Invalid template ID")
        
        // Validate ID format
        if (!id.matches(Regex("^[0-9]+$"))) {
            throw IllegalArgumentException("Invalid ID format")
        }
        
        val url = template.replace("{id}", id)
        val restTemplate = RestTemplate()
        val response = restTemplate.getForObject(url, String::class.java)
        return response ?: "No response"
    }
// {/fact}
}

@RestController
class GoodController14 {
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @GetMapping("/safe-query")
    fun good_case_14(@RequestParam query: String): String {
        // Use a fixed base URL
        val baseUrl = "https://api.example.com/search"
        
        // Sanitize query parameter
        // ok: kotlin-server-side-request-forgery
        val sanitizedQuery = ESAPI.encoder().encodeForURL(query)
        
        val fullUrl = "$baseUrl?q=$sanitizedQuery"
        val client = OkHttpClient()
        val request = Request.Builder()
            .url(fullUrl)
            .build()
        
        val response = client.newCall(request).execute()
        return response.body?.string() ?: "No response"
    }
// {/fact}
}

@RestController
class GoodController15 {
    private val allowedUrls = listOf(
        "https://api.example.com/data",
        "https://api.example.com/users",
        "https://api.example.com/products"
    )
    
// {fact rule=server-side-request-forgery@v1.0 defects=0}
    @GetMapping("/safe-url-check")
    fun good_case_15(@RequestParam url: String): String {
        // Check if URL is in the allowed list
        // ok: kotlin-server-side-request-forgery
        if (!allowedUrls.contains(url)) {
            throw SecurityException("URL not in allowed list")
        }
        
        val connection = URL(url).openConnection() as HttpURLConnection
        val response = connection.inputStream.bufferedReader().use { it.readText() }
        return response
    }
// {/fact}
}