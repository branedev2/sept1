import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.WebSettings
import android.os.Bundle
import android.app.Activity
import android.content.Intent
import android.net.Uri
import androidx.appcompat.app.AppCompatActivity
import android.webkit.JavascriptInterface
import android.webkit.ValueCallback
import android.widget.Toast
import android.content.Context
import java.net.URL
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_1(context: Context) {
    val webView = WebView(context)
    val webSettings = webView.settings
    // ruleid: kotlin-webviews-security
    webSettings.javaScriptEnabled = true
    
    // Load untrusted content from user input
    val userProvidedUrl = getUrlFromUserInput()
    webView.loadUrl(userProvidedUrl)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_2(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webviews-security
    webView.settings.javaScriptEnabled = true
    
    // Loading untrusted HTML directly
    val userInput = getUserInputFromRequest()
    webView.loadData(userInput, "text/html", "UTF-8")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_3(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webviews-security
    webView.settings.javaScriptEnabled = true
    
    // Fetching and loading content from an external source without validation
    val client = OkHttpClient()
    val request = Request.Builder()
        .url("https://example.com/user-content")
        .build()
    
    val response = client.newCall(request).execute()
    val content = response.body?.string() ?: ""
    webView.loadDataWithBaseURL(null, content, "text/html", "UTF-8", null)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_4(context: Context) {
    val webView = WebView(context)
    val settings = webView.settings
    // ruleid: kotlin-webviews-security
    settings.javaScriptEnabled = true
    
    // Adding JavaScript interface without proper validation
    webView.addJavascriptInterface(JavaScriptInterface(context), "Android")
    
    // Loading potentially malicious content
    val userContent = fetchUserGeneratedContent()
    webView.loadData(userContent, "text/html", "UTF-8")
}
// {/fact}

class JavaScriptInterface(private val context: Context) {
    @JavascriptInterface
    fun showToast(toast: String) {
        Toast.makeText(context, toast, Toast.LENGTH_SHORT).show()
    }
}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_5(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webviews-security
    webView.settings.javaScriptEnabled = true
    
    // Loading content from query parameter without sanitization
    val intent = Intent() // Simulating an intent with data
    val uri = intent.data
    val userProvidedContent = uri?.getQueryParameter("content") ?: ""
    webView.loadData(userProvidedContent, "text/html", "UTF-8")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_6(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webviews-security
    webView.settings.javaScriptEnabled = true
    webView.settings.allowFileAccess = true
    
    // Loading local file that might contain untrusted content
    val fileName = getFileNameFromUserInput()
    webView.loadUrl("file:///android_asset/$fileName")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_7(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webviews-security
    webView.settings.javaScriptEnabled = true
    
    // Evaluating JavaScript directly with user input
    val userScript = getUserProvidedScript()
    webView.evaluateJavascript("(function() { $userScript })()", null)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_8(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webviews-security
    webView.settings.javaScriptEnabled = true
    
    // Loading content from deep link
    val deepLinkUrl = getDeepLinkUrl()
    if (deepLinkUrl.startsWith("http")) {
        webView.loadUrl(deepLinkUrl)
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_9(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webviews-security
    webView.settings.javaScriptEnabled = true
    webView.settings.domStorageEnabled = true
    
    // Loading third-party content without validation
    val thirdPartyUrl = getThirdPartyContentUrl()
    webView.loadUrl(thirdPartyUrl)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_10(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webviews-security
    webView.settings.javaScriptEnabled = true
    
    // Constructing HTML with user input
    val userName = getUserName()
    val htmlContent = "<html><body><script>document.write('Hello, $userName!');</script></body></html>"
    webView.loadData(htmlContent, "text/html", "UTF-8")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_11(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webviews-security
    webView.settings.javaScriptEnabled = true
    
    // Loading content from shared preferences that might contain untrusted data
    val sharedPrefs = context.getSharedPreferences("user_content", Context.MODE_PRIVATE)
    val savedContent = sharedPrefs.getString("saved_html", "") ?: ""
    webView.loadData(savedContent, "text/html", "UTF-8")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_12(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webviews-security
    webView.settings.javaScriptEnabled = true
    
    // Loading content from intent extra
    val intent = Intent() // Simulating an intent
    val extraContent = intent.getStringExtra("web_content") ?: ""
    webView.loadData(extraContent, "text/html", "UTF-8")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_13(context: Context) {
    val webView = WebView(context)
    val settings = webView.settings
    // ruleid: kotlin-webviews-security
    settings.javaScriptEnabled = true
    settings.allowUniversalAccessFromFileURLs = true
    
    // Loading local file with universal access enabled
    webView.loadUrl("file:///android_asset/index.html")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_14(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webviews-security
    webView.settings.javaScriptEnabled = true
    
    // Dynamically injecting JavaScript based on user input
    val userInput = getUserComment()
    webView.loadUrl("javascript:updateComment('$userInput')")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
fun bad_case_15(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webviews-security
    webView.settings.javaScriptEnabled = true
    
    // Loading content from a QR code scan
    val qrCodeContent = getQrCodeScanResult()
    if (qrCodeContent.startsWith("http")) {
        webView.loadUrl(qrCodeContent)
    } else {
        webView.loadData(qrCodeContent, "text/html", "UTF-8")
    }
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_1(context: Context) {
    val webView = WebView(context)
    // ok: kotlin-webviews-security
    webView.settings.javaScriptEnabled = false
    
    // Load content with JavaScript disabled
    val userProvidedUrl = getUrlFromUserInput()
    webView.loadUrl(userProvidedUrl)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_2(context: Context) {
    val webView = WebView(context)
    // ok: kotlin-webviews-security
    // JavaScript remains disabled by default
    
    // Loading HTML content with JavaScript disabled
    val userInput = getUserInputFromRequest()
    webView.loadData(userInput, "text/html", "UTF-8")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_3(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Only loading from trusted sources with JavaScript disabled
    webView.loadUrl("https://trusted-domain.com")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_4(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Using a whitelist of allowed URLs
    val userProvidedUrl = getUrlFromUserInput()
    val allowedDomains = listOf("trusted-domain.com", "safe-site.org")
    
    val uri = Uri.parse(userProvidedUrl)
    val host = uri.host ?: ""
    
    if (allowedDomains.any { host.endsWith(it) }) {
        webView.loadUrl(userProvidedUrl)
    } else {
        // Handle untrusted URL
        showError(context, "Untrusted URL")
    }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_5(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Sanitizing user input before loading
    val userInput = getUserInputFromRequest()
    val sanitizedInput = sanitizeHtml(userInput)
    webView.loadData(sanitizedInput, "text/html", "UTF-8")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_6(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Using custom WebViewClient to intercept and validate URLs
    webView.webViewClient = object : WebViewClient() {
        override fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
            return if (isUrlSafe(url)) {
                false // Allow WebView to load the URL
            } else {
                true // Block the URL from loading
            }
        }
    }
    
    webView.loadUrl("https://trusted-domain.com")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_7(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Loading static content from assets
    webView.loadUrl("file:///android_asset/static_content.html")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_8(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Using Content Security Policy
    val csp = "Content-Security-Policy: default-src 'self'"
    val htmlContent = """
        <html>
        <head>
            <meta http-equiv="$csp">
        </head>
        <body>
            <h1>Secure Content</h1>
        </body>
        </html>
    """.trimIndent()
    
    webView.loadDataWithBaseURL(null, htmlContent, "text/html", "UTF-8", null)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_9(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Loading only trusted content with proper encoding
    val userName = getUserName()
    val encodedName = Uri.encode(userName)
    val htmlContent = "<html><body><h1>Hello, $encodedName!</h1></body></html>"
    webView.loadData(htmlContent, "text/html", "UTF-8")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_10(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Using a secure WebViewClient with SSL error handling
    webView.webViewClient = object : WebViewClient() {
        override fun onReceivedSslError(view: WebView, handler: android.webkit.SslErrorHandler, error: android.net.http.SslError) {
            // Don't proceed on SSL errors
            handler.cancel()
        }
    }
    
    webView.loadUrl("https://trusted-domain.com")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_11(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Only enabling JavaScript for specific trusted domains
    val url = getUrlFromUserInput()
    val uri = Uri.parse(url)
    val host = uri.host ?: ""
    
    if (host == "trusted-domain.com") {
        webView.settings.javaScriptEnabled = true
    } else {
        webView.settings.javaScriptEnabled = false
    }
    
    webView.loadUrl(url)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_12(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Using a secure configuration with JavaScript disabled
    webView.settings.apply {
        javaScriptEnabled = false
        allowFileAccess = false
        allowContentAccess = false
        allowFileAccessFromFileURLs = false
        allowUniversalAccessFromFileURLs = false
    }
    
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_13(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Using HTML escaping for user input
    val userComment = getUserComment()
    val escapedComment = escapeHtml(userComment)
    val htmlContent = "<html><body><div>$escapedComment</div></body></html>"
    webView.loadData(htmlContent, "text/html", "UTF-8")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_14(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Loading only static resources with no user input
    webView.loadUrl("file:///android_asset/about.html")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
fun good_case_15(context: Context) {
    val webView = WebView(context)
    
    // ok: kotlin-webviews-security
    // Using safe rendering with no JavaScript
    val content = """
        <html>
        <head>
            <style>
                body { font-family: sans-serif; }
            </style>
        </head>
        <body>
            <h1>Static Content</h1>
            <p>This is safe, static content with no JavaScript.</p>
        </body>
        </html>
    """.trimIndent()
    
    webView.loadDataWithBaseURL(null, content, "text/html", "UTF-8", null)
}
// {/fact}

// Helper functions (implementations not shown for brevity)
fun getUrlFromUserInput(): String = "https://example.com"
fun getUserInputFromRequest(): String = "<p>User input</p>"
fun fetchUserGeneratedContent(): String = "<p>User generated content</p>"
fun getFileNameFromUserInput(): String = "page.html"
fun getUserProvidedScript(): String = "console.log('Hello');"
fun getDeepLinkUrl(): String = "https://example.com/page"
fun getThirdPartyContentUrl(): String = "https://third-party.com/content"
fun getUserName(): String = "John Doe"
fun getUserComment(): String = "This is a comment"
fun getQrCodeScanResult(): String = "https://example.com"
fun showError(context: Context, message: String) { /* Implementation */ }
fun sanitizeHtml(input: String): String = input.replace("<script>", "").replace("</script>", "")
fun isUrlSafe(url: String): Boolean = url.startsWith("https://trusted-domain.com")
fun escapeHtml(input: String): String = input
    .replace("&", "&amp;")
    .replace("<", "&lt;")
    .replace(">", "&gt;")
    .replace("\"", "&quot;")
    .replace("'", "&#x27;")