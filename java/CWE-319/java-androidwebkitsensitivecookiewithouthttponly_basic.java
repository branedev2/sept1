import android.webkit.CookieManager;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.ValueCallback;
import android.os.Build;
import android.annotation.SuppressLint;
import android.content.Context;

public class AndroidWebViewCookieTests {

    // True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
    public void bad_case_1(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        cookieManager.setAcceptCookie(true);
        
        // ruleid: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://example.com", "sessionId=12345; Secure");
        webView.loadUrl("https://example.com");
    }

    public void bad_case_2(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        // ruleid: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://banking.example.com", "authToken=abc123; Secure; SameSite=Strict");
        webView.loadUrl("https://banking.example.com/account");
    }

    public void bad_case_3(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        String token = generateAuthToken();
        
        // ruleid: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://api.example.com", "apiKey=" + token + "; Secure");
        webView.loadUrl("https://api.example.com");
    }

    @SuppressLint("SetJavaScriptEnabled")
    public void bad_case_4(Context context) {
        WebView webView = new WebView(context);
        webView.getSettings().setJavaScriptEnabled(true);
        CookieManager cookieManager = CookieManager.getInstance();
        
        // ruleid: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://payment.example.com", "paymentToken=xyz789; Secure; SameSite=Strict; Max-Age=3600");
        webView.loadUrl("https://payment.example.com/checkout");
    }

    public void bad_case_5(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        cookieManager.setAcceptThirdPartyCookies(webView, true);
        
        // ruleid: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://auth.example.com", "refreshToken=rt12345; Secure; Path=/; Max-Age=86400");
        webView.loadUrl("https://auth.example.com/refresh");
    }

    public void bad_case_6(Context context) {
        WebView webView = new WebView(context);
        webView.setWebViewClient(new WebViewClient());
        CookieManager cookieManager = CookieManager.getInstance();
        
        String userId = "user123";
        // ruleid: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://example.com", "userId=" + userId + "; Secure");
        webView.loadUrl("https://example.com/profile");
    }

    public void bad_case_7(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        if (isUserLoggedIn()) {
            // ruleid: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://example.com", "sessionId=abc123; Secure; SameSite=Lax");
        }
        webView.loadUrl("https://example.com");
    }

    public void bad_case_8(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        String sessionData = getSessionData();
        
        // ruleid: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://example.com", "session=" + sessionData + "; Secure; Path=/api");
        webView.loadUrl("https://example.com/api/data");
    }

    public void bad_case_9(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        for (String domain : getTrustedDomains()) {
            // ruleid: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://" + domain, "authToken=token123; Secure");
        }
        webView.loadUrl("https://main.example.com");
    }

    public void bad_case_10(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        try {
            String token = fetchTokenFromServer();
            // ruleid: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://api.example.com", "bearerToken=" + token + "; Secure");
        } catch (Exception e) {
            e.printStackTrace();
        }
        webView.loadUrl("https://api.example.com");
    }

    @SuppressLint("SetJavaScriptEnabled")
    public void bad_case_11(Context context) {
        WebView webView = new WebView(context);
        webView.getSettings().setJavaScriptEnabled(true);
        CookieManager cookieManager = CookieManager.getInstance();
        
        String[] cookies = {"sessionId=123", "userId=456", "role=user"};
        for (String cookie : cookies) {
            // ruleid: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://example.com", cookie + "; Secure");
        }
        webView.loadUrl("https://example.com/dashboard");
    }

    public void bad_case_12(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        Map<String, String> cookieMap = getCookieData();
        for (Map.Entry<String, String> entry : cookieMap.entrySet()) {
            // ruleid: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://example.com", entry.getKey() + "=" + entry.getValue() + "; Secure");
        }
        webView.loadUrl("https://example.com");
    }

    public void bad_case_13(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        switch (getUserAuthLevel()) {
            case ADMIN:
                // ruleid: java-androidwebkitsensitivecookiewithouthttponly
                cookieManager.setCookie("https://admin.example.com", "adminToken=adm123; Secure");
                break;
            case USER:
                // ruleid: java-androidwebkitsensitivecookiewithouthttponly
                cookieManager.setCookie("https://example.com", "userToken=usr456; Secure");
                break;
        }
        webView.loadUrl("https://example.com");
    }

    public void bad_case_14(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        String cookieValue = "sessionId=" + generateSessionId() + "; Secure; SameSite=Strict; Max-Age=3600";
        // ruleid: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://example.com", cookieValue);
        webView.loadUrl("https://example.com/secure");
    }

    public void bad_case_15(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            cookieManager.setAcceptThirdPartyCookies(webView, false);
        }
        
        // ruleid: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://sso.example.com", "ssoToken=sso789; Secure; Path=/; SameSite=Strict");
        webView.loadUrl("https://sso.example.com/login");
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        // ok: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://example.com", "sessionId=12345; Secure; HttpOnly");
        webView.loadUrl("https://example.com");
    }

    public void good_case_2(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        // ok: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://banking.example.com", "authToken=abc123; Secure; HttpOnly; SameSite=Strict");
        webView.loadUrl("https://banking.example.com/account");
    }

    public void good_case_3(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        String token = generateAuthToken();
        
        // ok: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://api.example.com", "apiKey=" + token + "; Secure; HttpOnly");
        webView.loadUrl("https://api.example.com");
    }

    @SuppressLint("SetJavaScriptEnabled")
    public void good_case_4(Context context) {
        WebView webView = new WebView(context);
        webView.getSettings().setJavaScriptEnabled(true);
        CookieManager cookieManager = CookieManager.getInstance();
        
        // ok: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://payment.example.com", "paymentToken=xyz789; Secure; HttpOnly; SameSite=Strict; Max-Age=3600");
        webView.loadUrl("https://payment.example.com/checkout");
    }

    public void good_case_5(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        // Non-sensitive cookie doesn't need HttpOnly
        cookieManager.setCookie("https://example.com", "theme=dark; SameSite=Lax");
        webView.loadUrl("https://example.com");
    }

    public void good_case_6(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        // ok: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://auth.example.com", "refreshToken=rt12345; Secure; HttpOnly; Path=/; Max-Age=86400");
        webView.loadUrl("https://auth.example.com/refresh");
    }

    public void good_case_7(Context context) {
        WebView webView = new WebView(context);
        webView.setWebViewClient(new WebViewClient());
        CookieManager cookieManager = CookieManager.getInstance();
        
        String userId = "user123";
        // ok: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://example.com", "userId=" + userId + "; Secure; HttpOnly");
        webView.loadUrl("https://example.com/profile");
    }

    public void good_case_8(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        // Using a non-sensitive cookie that doesn't need HttpOnly
        cookieManager.setCookie("https://example.com", "language=en-US");
        webView.loadUrl("https://example.com");
    }

    public void good_case_9(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        if (isUserLoggedIn()) {
            // ok: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://example.com", "sessionId=abc123; Secure; HttpOnly; SameSite=Lax");
        }
        webView.loadUrl("https://example.com");
    }

    public void good_case_10(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        String sessionData = getSessionData();
        
        // ok: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://example.com", "session=" + sessionData + "; Secure; HttpOnly; Path=/api");
        webView.loadUrl("https://example.com/api/data");
    }

    public void good_case_11(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        for (String domain : getTrustedDomains()) {
            // ok: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://" + domain, "authToken=token123; Secure; HttpOnly");
        }
        webView.loadUrl("https://main.example.com");
    }

    public void good_case_12(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        // Using client-side only preferences, not sensitive auth data
        cookieManager.setCookie("https://example.com", "darkMode=true");
        cookieManager.setCookie("https://example.com", "fontSize=large");
        webView.loadUrl("https://example.com");
    }

    public void good_case_13(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        try {
            String token = fetchTokenFromServer();
            // ok: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://api.example.com", "bearerToken=" + token + "; Secure; HttpOnly");
        } catch (Exception e) {
            e.printStackTrace();
        }
        webView.loadUrl("https://api.example.com");
    }

    public void good_case_14(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        String[] cookies = {"sessionId=123", "userId=456", "role=user"};
        for (String cookie : cookies) {
            // ok: java-androidwebkitsensitivecookiewithouthttponly
            cookieManager.setCookie("https://example.com", cookie + "; Secure; HttpOnly");
        }
        webView.loadUrl("https://example.com/dashboard");
    }

    public void good_case_15(Context context) {
        WebView webView = new WebView(context);
        CookieManager cookieManager = CookieManager.getInstance();
        
        String cookieValue = "sessionId=" + generateSessionId() + "; Secure; HttpOnly; SameSite=Strict; Max-Age=3600";
        // ok: java-androidwebkitsensitivecookiewithouthttponly
        cookieManager.setCookie("https://example.com", cookieValue);
        webView.loadUrl("https://example.com/secure");
    }
    
    // Helper methods to make the examples compile
    private String generateAuthToken() {
        return "generated-token-123";
    }
    
    private boolean isUserLoggedIn() {
        return true;
    }
    
    private String getSessionData() {
        return "session-data-456";
    }
    
    private String[] getTrustedDomains() {
        return new String[]{"example.com", "api.example.com"};
    }
    
    private String fetchTokenFromServer() throws Exception {
        return "server-token-789";
    }
    
    private Map<String, String> getCookieData() {
        Map<String, String> map = new HashMap<>();
        map.put("sessionId", "abc123");
        map.put("userId", "user456");
        return map;
    }
    
    private enum UserAuthLevel {
        ADMIN, USER
    }
    
    private UserAuthLevel getUserAuthLevel() {
        return UserAuthLevel.USER;
    }
    
    private String generateSessionId() {
        return "session-" + System.currentTimeMillis();
    }
}
// {/fact}