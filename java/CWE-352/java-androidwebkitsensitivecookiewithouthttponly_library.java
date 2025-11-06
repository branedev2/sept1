import android.webkit.CookieManager;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebSettings;
import android.os.Build;
import android.content.Context;
import android.net.http.SslError;
import android.webkit.SslErrorHandler;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebStorage;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.HttpAuthHandler;
import android.webkit.ClientCertRequest;
import android.webkit.CookieSyncManager;
import androidx.webkit.WebViewCompat;
import androidx.webkit.WebViewFeature;
import androidx.webkit.WebSettingsCompat;
import androidx.webkit.ServiceWorkerControllerCompat;
import androidx.webkit.ServiceWorkerClientCompat;
import java.net.URL;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Map;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.HttpUrl;
import com.squareup.okhttp.JavaNetCookieJar;
import java.net.CookieHandler;
import java.net.CookiePolicy;
import java.net.CookieStore;
import org.apache.http.client.CookieStore as ApacheCookieStore;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

// Security Issue: Creating sensitive cookies in Android WebView without the HttpOnly attribute

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(Context context) {
    // Standard Android WebView with CookieManager setting sensitive cookie without HttpOnly
    WebView webView = new WebView(context);
    CookieManager cookieManager = CookieManager.getInstance();
    cookieManager.setAcceptCookie(true);
    
    // ruleid: java-androidwebkitsensitivecookiewithouthttponly
    cookieManager.setCookie("https://example.com", "sessionId=12345; Secure");
    
    webView.loadUrl("https://example.com");
}

public void bad_case_2(Context context) {
    // Android WebView with custom WebViewClient setting auth token cookie without HttpOnly
    WebView webView = new WebView(context);
    webView.setWebViewClient(new WebViewClient() {
        @Override
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ruleid: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://api.example.com", "authToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9; Secure");
        }
    });
    webView.loadUrl("https://api.example.com/login");
}

public void bad_case_3(Context context) {
    // WebView with JavaScript interface and sensitive cookie set via JavaScript
    WebView webView = new WebView(context);
    WebSettings webSettings = webView.getSettings();
    webSettings.setJavaScriptEnabled(true);
    
    webView.evaluateJavascript("(function() {" +
        "var date = new Date();" +
        "date.setTime(date.getTime() + (7 * 24 * 60 * 60 * 1000));" +
        "var expires = '; expires=' + date.toUTCString();" +
        
        // ruleid: java-androidwebkitsensitivecookiewithouthttponly
        "document.cookie = 'userToken=abcdef123456' + expires + '; path=/; Secure';" +
        
        "return true;" +
    "})()", null);
    
    webView.loadUrl("https://example.com/dashboard");
}

public void bad_case_4(Context context) {
    // WebView with cookie set for OAuth authentication without HttpOnly
    WebView webView = new WebView(context);
    CookieManager cookieManager = CookieManager.getInstance();
    cookieManager.setAcceptThirdPartyCookies(webView, true);
    
    // ruleid: java-androidwebkitsensitivecookiewithouthttponly
    cookieManager.setCookie("https://oauth.example.org", "oauth_token=secret_token_value; Secure; SameSite=Strict");
    
    webView.loadUrl("https://oauth.example.org/authorize");
}

public void bad_case_5(Context context) {
    // WebView with sensitive payment information cookie without HttpOnly
    WebView webView = new WebView(context);
    webView.setWebViewClient(new WebViewClient());
    CookieManager cookieManager = CookieManager.getInstance();
    
    // ruleid: java-androidwebkitsensitivecookiewithouthttponly
    cookieManager.setCookie("https://payment.example.com", "paymentId=pay_12345; Secure");
    
    webView.loadUrl("https://payment.example.com/checkout");
}

public void bad_case_6(Context context) {
    // WebView with sensitive cookie set after SSL error handling
    WebView webView = new WebView(context);
    webView.setWebViewClient(new WebViewClient() {
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            handler.proceed(); // Ignoring SSL errors
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ruleid: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://banking.example.com", "accountToken=secret123; Secure");
        }
    });
    webView.loadUrl("https://banking.example.com");
}

public void bad_case_7(Context context) {
    // WebView with cookie set via JavaScript interface
    WebView webView = new WebView(context);
    WebSettings webSettings = webView.getSettings();
    webSettings.setJavaScriptEnabled(true);
    
    class CookieSetter {
        @android.webkit.JavascriptInterface
        public void setCookie() {
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ruleid: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://app.example.com", "sessionKey=very_secret_session_key; Secure");
        }
    }
    
    webView.addJavascriptInterface(new CookieSetter(), "cookieSetter");
    webView.loadUrl("https://app.example.com");
}

public void bad_case_8(Context context) {
    // WebView with cookie set for WebRTC authentication
    WebView webView = new WebView(context);
    WebSettings settings = webView.getSettings();
    settings.setMediaPlaybackRequiresUserGesture(false);
    settings.setJavaScriptEnabled(true);
    
    CookieManager cookieManager = CookieManager.getInstance();
    
    // ruleid: java-androidwebkitsensitivecookiewithouthttponly
    cookieManager.setCookie("https://webrtc.example.com", "rtcAuthToken=rtc_token_12345; Secure");
    
    webView.loadUrl("https://webrtc.example.com/call");
}

public void bad_case_9(Context context) {
    // WebView with cookie set for file download authentication
    WebView webView = new WebView(context);
    webView.setWebChromeClient(new WebChromeClient() {
        @Override
        public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> filePathCallback, 
                                        FileChooserParams fileChooserParams) {
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ruleid: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://files.example.com", "downloadToken=download_auth_token; Secure");
            
            return true;
        }
    });
    webView.loadUrl("https://files.example.com/download");
}

public void bad_case_10(Context context) {
    // WebView with cookie set for WebSQL database access
    WebView webView = new WebView(context);
    WebSettings settings = webView.getSettings();
    settings.setJavaScriptEnabled(true);
    settings.setDatabaseEnabled(true);
    
    webView.setWebChromeClient(new WebChromeClient() {
        @Override
        public void onExceededDatabaseQuota(String url, String databaseIdentifier, long quota,
                                          long estimatedDatabaseSize, long totalQuota,
                                          WebStorage.QuotaUpdater quotaUpdater) {
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ruleid: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://db.example.com", "dbAccessKey=db_secret_key; Secure");
            
            quotaUpdater.updateQuota(estimatedDatabaseSize * 2);
        }
    });
    webView.loadUrl("https://db.example.com");
}

public void bad_case_11(Context context) {
    // WebView with cookie set for HTTP authentication
    WebView webView = new WebView(context);
    webView.setWebViewClient(new WebViewClient() {
        @Override
        public void onReceivedHttpAuthRequest(WebView view, HttpAuthHandler handler, String host, String realm) {
            handler.proceed("username", "password");
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ruleid: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://" + host, "basicAuthToken=basic_auth_token_value; Secure");
        }
    });
    webView.loadUrl("https://secure.example.com");
}

public void bad_case_12(Context context) {
    // WebView with cookie set for client certificate authentication
    WebView webView = new WebView(context);
    webView.setWebViewClient(new WebViewClient() {
        @Override
        public void onReceivedClientCertRequest(WebView view, ClientCertRequest request) {
            // Handle client cert request
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ruleid: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://cert.example.com", "certAuthId=certificate_auth_id; Secure");
            
            request.cancel();
        }
    });
    webView.loadUrl("https://cert.example.com");
}

public void bad_case_13(Context context) {
    // WebView with cookie set for service worker registration
    if (WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_BASIC_USAGE)) {
        ServiceWorkerControllerCompat controller = ServiceWorkerControllerCompat.getInstance();
        controller.setServiceWorkerClient(new ServiceWorkerClientCompat() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebResourceRequest request) {
                CookieManager cookieManager = CookieManager.getInstance();
                
                // ruleid: java-androidwebkitsensitivecookiewithouthttponly
                cookieManager.setCookie("https://pwa.example.com", "swRegistrationToken=sw_token_123; Secure");
                
                return null;
            }
        });
        
        WebView webView = new WebView(context);
        webView.loadUrl("https://pwa.example.com");
    }
}

public void bad_case_14(Context context) {
    // WebView with cookie set for IndexedDB access
    WebView webView = new WebView(context);
    WebSettings settings = webView.getSettings();
    settings.setJavaScriptEnabled(true);
    settings.setDomStorageEnabled(true);
    
    CookieManager cookieManager = CookieManager.getInstance();
    
    // ruleid: java-androidwebkitsensitivecookiewithouthttponly
    cookieManager.setCookie("https://storage.example.com", "indexedDBToken=idb_access_token; Secure");
    
    webView.loadUrl("https://storage.example.com/app");
}

public void bad_case_15(Context context) {
    // Legacy CookieSyncManager with sensitive cookie without HttpOnly
    CookieSyncManager.createInstance(context);
    CookieManager cookieManager = CookieManager.getInstance();
    
    // ruleid: java-androidwebkitsensitivecookiewithouthttponly
    cookieManager.setCookie("https://legacy.example.com", "legacyAuthToken=old_token_value; Secure");
    
    CookieSyncManager.getInstance().sync();
    
    WebView webView = new WebView(context);
    webView.loadUrl("https://legacy.example.com");
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(Context context) {
    // Standard Android WebView with CookieManager setting sensitive cookie with HttpOnly
    WebView webView = new WebView(context);
    CookieManager cookieManager = CookieManager.getInstance();
    cookieManager.setAcceptCookie(true);
    
    // ok: java-androidwebkitsensitivecookiewithouthttponly
    cookieManager.setCookie("https://example.com", "sessionId=12345; Secure; HttpOnly");
    
    webView.loadUrl("https://example.com");
}

public void good_case_2(Context context) {
    // Android WebView with custom WebViewClient setting auth token cookie with HttpOnly
    WebView webView = new WebView(context);
    webView.setWebViewClient(new WebViewClient() {
        @Override
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ok: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://api.example.com", "authToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9; Secure; HttpOnly");
        }
    });
    webView.loadUrl("https://api.example.com/login");
}

public void good_case_3(Context context) {
    // WebView with JavaScript interface and non-sensitive cookie set via JavaScript
    WebView webView = new WebView(context);
    WebSettings webSettings = webView.getSettings();
    webSettings.setJavaScriptEnabled(true);
    
    // ok: java-androidwebkitsensitivecookiewithouthttponly
    webView.evaluateJavascript("(function() {" +
        "var date = new Date();" +
        "date.setTime(date.getTime() + (7 * 24 * 60 * 60 * 1000));" +
        "var expires = '; expires=' + date.toUTCString();" +
        "document.cookie = 'theme=dark' + expires + '; path=/; Secure';" +
        "return true;" +
    "})()", null);
    
    webView.loadUrl("https://example.com/dashboard");
}

public void good_case_4(Context context) {
    // WebView with cookie set for OAuth authentication with HttpOnly
    WebView webView = new WebView(context);
    CookieManager cookieManager = CookieManager.getInstance();
    cookieManager.setAcceptThirdPartyCookies(webView, true);
    
    // ok: java-androidwebkitsensitivecookiewithouthttponly
    cookieManager.setCookie("https://oauth.example.org", "oauth_token=secret_token_value; Secure; HttpOnly; SameSite=Strict");
    
    webView.loadUrl("https://oauth.example.org/authorize");
}

public void good_case_5(Context context) {
    // WebView with sensitive payment information cookie with HttpOnly
    WebView webView = new WebView(context);
    webView.setWebViewClient(new WebViewClient());
    CookieManager cookieManager = CookieManager.getInstance();
    
    // ok: java-androidwebkitsensitivecookiewithouthttponly
    cookieManager.setCookie("https://payment.example.com", "paymentId=pay_12345; Secure; HttpOnly");
    
    webView.loadUrl("https://payment.example.com/checkout");
}

public void good_case_6(Context context) {
    // WebView with sensitive cookie set after SSL error handling with HttpOnly
    WebView webView = new WebView(context);
    webView.setWebViewClient(new WebViewClient() {
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            handler.cancel(); // Properly handling SSL errors
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ok: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://banking.example.com", "accountToken=secret123; Secure; HttpOnly");
        }
    });
    webView.loadUrl("https://banking.example.com");
}

public void good_case_7(Context context) {
    // WebView with cookie set via JavaScript interface with HttpOnly
    WebView webView = new WebView(context);
    WebSettings webSettings = webView.getSettings();
    webSettings.setJavaScriptEnabled(true);
    
    class CookieSetter {
        @android.webkit.JavascriptInterface
        public void setCookie() {
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ok: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://app.example.com", "sessionKey=very_secret_session_key; Secure; HttpOnly");
        }
    }
    
    webView.addJavascriptInterface(new CookieSetter(), "cookieSetter");
    webView.loadUrl("https://app.example.com");
}

public void good_case_8(Context context) {
    // WebView with cookie set for WebRTC authentication with HttpOnly
    WebView webView = new WebView(context);
    WebSettings settings = webView.getSettings();
    settings.setMediaPlaybackRequiresUserGesture(false);
    settings.setJavaScriptEnabled(true);
    
    CookieManager cookieManager = CookieManager.getInstance();
    
    // ok: java-androidwebkitsensitivecookiewithouthttponly
    cookieManager.setCookie("https://webrtc.example.com", "rtcAuthToken=rtc_token_12345; Secure; HttpOnly");
    
    webView.loadUrl("https://webrtc.example.com/call");
}

public void good_case_9(Context context) {
    // WebView with cookie set for file download authentication with HttpOnly
    WebView webView = new WebView(context);
    webView.setWebChromeClient(new WebChromeClient() {
        @Override
        public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> filePathCallback, 
                                        FileChooserParams fileChooserParams) {
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ok: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://files.example.com", "downloadToken=download_auth_token; Secure; HttpOnly");
            
            return true;
        }
    });
    webView.loadUrl("https://files.example.com/download");
}

public void good_case_10(Context context) {
    // WebView with cookie set for WebSQL database access with HttpOnly
    WebView webView = new WebView(context);
    WebSettings settings = webView.getSettings();
    settings.setJavaScriptEnabled(true);
    settings.setDatabaseEnabled(true);
    
    webView.setWebChromeClient(new WebChromeClient() {
        @Override
        public void onExceededDatabaseQuota(String url, String databaseIdentifier, long quota,
                                          long estimatedDatabaseSize, long totalQuota,
                                          WebStorage.QuotaUpdater quotaUpdater) {
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ok: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://db.example.com", "dbAccessKey=db_secret_key; Secure; HttpOnly");
            
            quotaUpdater.updateQuota(estimatedDatabaseSize * 2);
        }
    });
    webView.loadUrl("https://db.example.com");
}

public void good_case_11(Context context) {
    // WebView with cookie set for HTTP authentication with HttpOnly
    WebView webView = new WebView(context);
    webView.setWebViewClient(new WebViewClient() {
        @Override
        public void onReceivedHttpAuthRequest(WebView view, HttpAuthHandler handler, String host, String realm) {
            handler.proceed("username", "password");
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ok: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://" + host, "basicAuthToken=basic_auth_token_value; Secure; HttpOnly");
        }
    });
    webView.loadUrl("https://secure.example.com");
}

public void good_case_12(Context context) {
    // WebView with cookie set for client certificate authentication with HttpOnly
    WebView webView = new WebView(context);
    webView.setWebViewClient(new WebViewClient() {
        @Override
        public void onReceivedClientCertRequest(WebView view, ClientCertRequest request) {
            // Handle client cert request
            CookieManager cookieManager = CookieManager.getInstance();
            
            // ok: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://cert.example.com", "certAuthId=certificate_auth_id; Secure; HttpOnly");
            
            request.cancel();
        }
    });
    webView.loadUrl("https://cert.example.com");
}

public void good_case_13(Context context) {
    // WebView with cookie set for service worker registration with HttpOnly
    if (WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_BASIC_USAGE)) {
        ServiceWorkerControllerCompat controller = ServiceWorkerControllerCompat.getInstance();
        controller.setServiceWorkerClient(new ServiceWorkerClientCompat() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebResourceRequest request) {
                CookieManager cookieManager = CookieManager.getInstance();
                
                // ok: java-androidwebkitsensitivecookiewithouthttponly
                cookieManager.setCookie("https://pwa.example.com", "swRegistrationToken=sw_token_123; Secure; HttpOnly");
                
                return null;
            }
        });
        
        WebView webView = new WebView(context);
        webView.loadUrl("https://pwa.example.com");
    }
}

public void good_case_14(Context context) {
    // WebView with cookie set for IndexedDB access with HttpOnly
    WebView webView = new WebView(context);
    WebSettings settings = webView.getSettings();
    settings.setJavaScriptEnabled(true);
    settings.setDomStorageEnabled(true);
    
    CookieManager cookieManager = CookieManager.getInstance();
    
    // ok: java-androidwebkitsensitivecookiewithouthttponly
    cookieManager.setCookie("https://storage.example.com", "indexedDBToken=idb_access_token; Secure; HttpOnly");
    
    webView.loadUrl("https://storage.example.com/app");
}

public void good_case_15(Context context) {
    // Legacy CookieSyncManager with sensitive cookie with HttpOnly
    CookieSyncManager.createInstance(context);
    CookieManager cookieManager = CookieManager.getInstance();
    
    // ok: java-androidwebkitsensitivecookiewithouthttponly
    cookieManager.setCookie("https://legacy.example.com", "legacyAuthToken=old_token_value; Secure; HttpOnly");
    
    CookieSyncManager.getInstance().sync();
    
    WebView webView = new WebView(context);
    webView.loadUrl("https://legacy.example.com");
}