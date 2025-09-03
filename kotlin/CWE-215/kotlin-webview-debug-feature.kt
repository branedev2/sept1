import android.os.Bundle
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.WebChromeClient
import androidx.appcompat.app.AppCompatActivity
import android.content.Context
import android.webkit.WebSettings
import android.util.Log
import android.content.pm.ApplicationInfo
import android.os.Build

// True Positive Examples (Vulnerable Code)

// {fact rule=debug-information-exposure@v1.0 defects=1}
fun bad_case_1(webView: WebView) {
    // ruleid: kotlin-webview-debug-feature
    webView.setWebContentsDebuggingEnabled(true)
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=debug-information-exposure@v1.0 defects=1}
fun bad_case_2(context: Context) {
    val webView = WebView(context)
    // ruleid: kotlin-webview-debug-feature
    WebView.setWebContentsDebuggingEnabled(true)
    webView.loadUrl("https://example.com/secure")
}
// {/fact}

class BadActivity1 : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        // ruleid: kotlin-webview-debug-feature
        WebView.setWebContentsDebuggingEnabled(true)
        webView.loadUrl("https://example.com")
        setContentView(webView)
    }
}

// {fact rule=debug-information-exposure@v1.0 defects=1}
fun bad_case_3(webView: WebView, isDebug: Boolean) {
    // Even with a condition, enabling debugging is still a vulnerability
    if (isDebug) {
        // ruleid: kotlin-webview-debug-feature
        webView.setWebContentsDebuggingEnabled(true)
    }
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=debug-information-exposure@v1.0 defects=1}
fun bad_case_4(webView: WebView) {
    val settings = webView.settings
    settings.javaScriptEnabled = true
    // ruleid: kotlin-webview-debug-feature
    WebView.setWebContentsDebuggingEnabled(true)
    webView.webViewClient = WebViewClient()
    webView.loadUrl("https://example.com")
}
// {/fact}

class BadActivity2 : AppCompatActivity() {
    private lateinit var webView: WebView
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        webView = WebView(this)
        setupWebView()
        setContentView(webView)
    }
    
    private fun setupWebView() {
        webView.settings.javaScriptEnabled = true
        // ruleid: kotlin-webview-debug-feature
        WebView.setWebContentsDebuggingEnabled(true)
        webView.loadUrl("https://example.com")
    }
}

// {fact rule=debug-information-exposure@v1.0 defects=1}
fun bad_case_5(context: Context) {
    val webView = WebView(context)
    webView.settings.apply {
        javaScriptEnabled = true
        domStorageEnabled = true
    }
    // ruleid: kotlin-webview-debug-feature
    WebView.setWebContentsDebuggingEnabled(true)
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=debug-information-exposure@v1.0 defects=1}
fun bad_case_6(context: Context) {
    val webView = WebView(context)
    val debuggingEnabled = true
    // ruleid: kotlin-webview-debug-feature
    WebView.setWebContentsDebuggingEnabled(debuggingEnabled)
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=debug-information-exposure@v1.0 defects=1}
fun bad_case_7(context: Context, url: String) {
    val webView = WebView(context)
    webView.settings.javaScriptEnabled = true
    // ruleid: kotlin-webview-debug-feature
    webView.setWebContentsDebuggingEnabled(true)
    webView.loadUrl(url)
}
// {/fact}

class BadWebViewManager {
// {fact rule=debug-information-exposure@v1.0 defects=1}
    fun initializeWebView(context: Context): WebView {
        val webView = WebView(context)
        // ruleid: kotlin-webview-debug-feature
        WebView.setWebContentsDebuggingEnabled(true)
        webView.settings.javaScriptEnabled = true
        return webView
    }
// {/fact}
}

// {fact rule=debug-information-exposure@v1.0 defects=1}
fun bad_case_8(webView: WebView) {
    try {
        // ruleid: kotlin-webview-debug-feature
        WebView.setWebContentsDebuggingEnabled(true)
        webView.loadUrl("https://example.com")
    } catch (e: Exception) {
        Log.e("WebView", "Error setting up WebView", e)
    }
}
// {/fact}

// {fact rule=debug-information-exposure@v1.0 defects=1}
fun bad_case_9(context: Context) {
    val webView = WebView(context)
    val settings = webView.settings
    settings.javaScriptEnabled = true
    
    // ruleid: kotlin-webview-debug-feature
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
        WebView.setWebContentsDebuggingEnabled(true)
    }
    
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=debug-information-exposure@v1.0 defects=1}
fun bad_case_10(context: Context, isDebuggable: Boolean) {
    val webView = WebView(context)
    // ruleid: kotlin-webview-debug-feature
    WebView.setWebContentsDebuggingEnabled(isDebuggable || true) // Always true
    webView.loadUrl("https://example.com")
}
// {/fact}

class BadWebViewFactory {
    companion object {
        fun createWebView(context: Context): WebView {
            val webView = WebView(context)
            // ruleid: kotlin-webview-debug-feature
            WebView.setWebContentsDebuggingEnabled(true)
            return webView
        }
    }
}

// {fact rule=debug-information-exposure@v1.0 defects=1}
fun bad_case_11(context: Context) {
    val webView = WebView(context)
    webView.settings.apply {
        javaScriptEnabled = true
        domStorageEnabled = true
        databaseEnabled = true
    }
    
    // ruleid: kotlin-webview-debug-feature
    when (BuildConfig.DEBUG) {
        true -> WebView.setWebContentsDebuggingEnabled(true)
        false -> WebView.setWebContentsDebuggingEnabled(true) // Still enabled in production
    }
    
    webView.loadUrl("https://example.com")
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=debug-information-exposure@v1.0 defects=0}
fun good_case_1(webView: WebView) {
    // ok: kotlin-webview-debug-feature
    webView.setWebContentsDebuggingEnabled(false)
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=debug-information-exposure@v1.0 defects=0}
fun good_case_2(context: Context) {
    val webView = WebView(context)
    // ok: kotlin-webview-debug-feature
    WebView.setWebContentsDebuggingEnabled(false)
    webView.loadUrl("https://example.com/secure")
}
// {/fact}

class GoodActivity1 : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        // Debugging is not enabled
        // ok: kotlin-webview-debug-feature
        webView.loadUrl("https://example.com")
        setContentView(webView)
    }
}

// {fact rule=debug-information-exposure@v1.0 defects=0}
fun good_case_3(webView: WebView, isDebug: Boolean) {
    // Only enable debugging in debug builds
    // ok: kotlin-webview-debug-feature
    if (BuildConfig.DEBUG && isDebug) {
        webView.setWebContentsDebuggingEnabled(true)
    } else {
        webView.setWebContentsDebuggingEnabled(false)
    }
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=debug-information-exposure@v1.0 defects=0}
fun good_case_4(webView: WebView) {
    val settings = webView.settings
    settings.javaScriptEnabled = true
    // ok: kotlin-webview-debug-feature
    // No debugging enabled
    webView.webViewClient = WebViewClient()
    webView.loadUrl("https://example.com")
}
// {/fact}

class GoodActivity2 : AppCompatActivity() {
    private lateinit var webView: WebView
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        webView = WebView(this)
        setupWebView()
        setContentView(webView)
    }
    
    private fun setupWebView() {
        webView.settings.javaScriptEnabled = true
        // ok: kotlin-webview-debug-feature
        // Only enable debugging in debug builds
        if (0 != (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE)) {
            WebView.setWebContentsDebuggingEnabled(true)
        }
        webView.loadUrl("https://example.com")
    }
}

// {fact rule=debug-information-exposure@v1.0 defects=0}
fun good_case_5(context: Context) {
    val webView = WebView(context)
    webView.settings.apply {
        javaScriptEnabled = true
        domStorageEnabled = true
    }
    // ok: kotlin-webview-debug-feature
    // Explicitly disabled
    WebView.setWebContentsDebuggingEnabled(false)
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=debug-information-exposure@v1.0 defects=0}
fun good_case_6(context: Context) {
    val webView = WebView(context)
    // ok: kotlin-webview-debug-feature
    // No debugging enabled
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=debug-information-exposure@v1.0 defects=0}
fun good_case_7(context: Context, url: String) {
    val webView = WebView(context)
    webView.settings.javaScriptEnabled = true
    // ok: kotlin-webview-debug-feature
    // Only enable in debug builds
    if (BuildConfig.DEBUG) {
        WebView.setWebContentsDebuggingEnabled(true)
    }
    webView.loadUrl(url)
}
// {/fact}

class GoodWebViewManager {
// {fact rule=debug-information-exposure@v1.0 defects=0}
    fun initializeWebView(context: Context): WebView {
        val webView = WebView(context)
        // ok: kotlin-webview-debug-feature
        // No debugging enabled
        webView.settings.javaScriptEnabled = true
        return webView
    }
// {/fact}
}

// {fact rule=debug-information-exposure@v1.0 defects=0}
fun good_case_8(webView: WebView) {
    try {
        // ok: kotlin-webview-debug-feature
        WebView.setWebContentsDebuggingEnabled(false)
        webView.loadUrl("https://example.com")
    } catch (e: Exception) {
        Log.e("WebView", "Error setting up WebView", e)
    }
}
// {/fact}

// {fact rule=debug-information-exposure@v1.0 defects=0}
fun good_case_9(context: Context) {
    val webView = WebView(context)
    val settings = webView.settings
    settings.javaScriptEnabled = true
    
    // ok: kotlin-webview-debug-feature
    // Explicitly disabled for all API levels
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
        WebView.setWebContentsDebuggingEnabled(false)
    }
    
    webView.loadUrl("https://example.com")
}
// {/fact}

// {fact rule=debug-information-exposure@v1.0 defects=0}
fun good_case_10(context: Context, isDebuggable: Boolean) {
    val webView = WebView(context)
    // ok: kotlin-webview-debug-feature
    // Only enable in debug mode
    val debuggable = 0 != (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE)
    if (debuggable && isDebuggable) {
        WebView.setWebContentsDebuggingEnabled(true)
    }
    webView.loadUrl("https://example.com")
}
// {/fact}

class GoodWebViewFactory {
    companion object {
        fun createWebView(context: Context): WebView {
            val webView = WebView(context)
            // ok: kotlin-webview-debug-feature
            // No debugging enabled
            return webView
        }
    }
}

// {fact rule=debug-information-exposure@v1.0 defects=0}
fun good_case_11(context: Context) {
    val webView = WebView(context)
    webView.settings.apply {
        javaScriptEnabled = true
        domStorageEnabled = true
        databaseEnabled = true
    }
    
    // ok: kotlin-webview-debug-feature
    when (BuildConfig.DEBUG) {
        true -> WebView.setWebContentsDebuggingEnabled(true)
        false -> WebView.setWebContentsDebuggingEnabled(false) // Disabled in production
    }
    
    webView.loadUrl("https://example.com")
}
// {/fact}

// Assuming BuildConfig class exists for the examples
object BuildConfig {
    const val DEBUG = false // Simulating production build
}