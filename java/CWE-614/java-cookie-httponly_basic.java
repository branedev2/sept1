import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import jakarta.servlet.http.Cookie as JakartaCookie;
import jakarta.servlet.http.HttpServletResponse as JakartaHttpServletResponse;

public class CookieSecurityExamples {

    // True Positives (Vulnerable/Insecure Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
    public void bad_case_1(HttpServletResponse response) {
        // ruleid: java-cookie-httponly
        Cookie cookie = new Cookie("sessionId", "abc123");
        cookie.setMaxAge(86400);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    public void bad_case_2(HttpServletResponse response) {
        // ruleid: java-cookie-httponly
        Cookie cookie = new Cookie("authToken", "xyz789");
        cookie.setMaxAge(3600);
        cookie.setSecure(true); // Setting secure but missing httpOnly
        response.addCookie(cookie);
    }

    public void bad_case_3(HttpServletResponse response) {
        // ruleid: java-cookie-httponly
        Cookie cookie = new Cookie("userId", "12345");
        cookie.setHttpOnly(false); // Explicitly setting httpOnly to false
        cookie.setPath("/api");
        response.addCookie(cookie);
    }

    @RestController
    public class BadCookieController1 {
        @GetMapping("/bad-cookie-4")
        public void bad_case_4(HttpServletResponse response) {
            // ruleid: java-cookie-httponly
            Cookie userCookie = new Cookie("preferences", "theme=dark");
            userCookie.setMaxAge(604800); // 1 week
            userCookie.setDomain("example.com");
            response.addCookie(userCookie);
        }
    }

    public void bad_case_5(HttpServletResponse response) {
        // ruleid: java-cookie-httponly
        Cookie cookie = new Cookie("rememberMe", "true");
        cookie.setHttpOnly(true);
        // Missing SameSite attribute
        response.addCookie(cookie);
    }

    public void bad_case_6(JakartaHttpServletResponse response) {
        // ruleid: java-cookie-httponly
        JakartaCookie cookie = new JakartaCookie("cart", "item1,item2");
        cookie.setMaxAge(86400);
        cookie.setPath("/shop");
        response.addCookie(cookie);
    }

    public ResponseEntity<String> bad_case_7() {
        // ruleid: java-cookie-httponly
        ResponseCookie cookie = ResponseCookie.from("tracking", "visitor123")
                .maxAge(2592000) // 30 days
                .path("/")
                .build();
        
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body("Cookie set");
    }

    public void bad_case_8(HttpServletResponse response) {
        // ruleid: java-cookie-httponly
        Cookie cookie = new Cookie("language", "en-US");
        if (isSecureEnvironment()) {
            cookie.setSecure(true);
        }
        // No httpOnly setting
        response.addCookie(cookie);
    }

    public ResponseEntity<String> bad_case_9() {
        // ruleid: java-cookie-httponly
        ResponseCookie cookie = ResponseCookie.from("analyticsId", "UA12345")
                .httpOnly(false) // Explicitly set to false
                .path("/")
                .build();
        
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body("Analytics cookie set");
    }

    public void bad_case_10(HttpServletResponse response, String token) {
        // ruleid: java-cookie-httponly
        Cookie authCookie = new Cookie("authToken", token);
        authCookie.setMaxAge(-1); // Session cookie
        authCookie.setPath("/");
        authCookie.setSecure(true);
        // Missing httpOnly
        response.addCookie(authCookie);
    }

    public void bad_case_11(HttpServletResponse response) {
        // ruleid: java-cookie-httponly
        String cookieValue = "sessionId=abc123; Path=/; Max-Age=86400";
        response.setHeader("Set-Cookie", cookieValue);
        // Missing httpOnly and SameSite in header string
    }

    public ResponseEntity<String> bad_case_12() {
        // ruleid: java-cookie-httponly
        ResponseCookie cookie = ResponseCookie.from("sessionId", "abc123")
                .sameSite("Lax") // Not set to strict
                .httpOnly(true)
                .path("/")
                .build();
        
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body("Session cookie set");
    }

    public void bad_case_13(HttpServletResponse response) {
        // ruleid: java-cookie-httponly
        Cookie cookie1 = new Cookie("preference1", "value1");
        Cookie cookie2 = new Cookie("preference2", "value2");
        
        // First cookie is secure but second isn't fully secure
        cookie1.setHttpOnly(true);
        cookie1.setSecure(true);
        
        response.addCookie(cookie1);
        response.addCookie(cookie2); // Missing httpOnly
    }

    public void bad_case_14(HttpServletResponse response) {
        for (String userData : getUserDataList()) {
            // ruleid: java-cookie-httponly
            Cookie userCookie = new Cookie("userData", userData);
            userCookie.setPath("/");
            response.addCookie(userCookie); // Missing httpOnly
        }
    }

    public ResponseEntity<String> bad_case_15() {
        // ruleid: java-cookie-httponly
        String cookieString = "sessionId=xyz789; Path=/; HttpOnly";
        // Missing SameSite attribute in the manually constructed cookie
        
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookieString)
                .body("Cookie set");
    }

    // True Negatives (Safe/Secure Code)

    public void good_case_1(HttpServletResponse response) {
        // ok: java-cookie-httponly
        Cookie cookie = new Cookie("sessionId", "abc123");
        cookie.setMaxAge(86400);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        response.addCookie(cookie);
        response.setHeader("Set-Cookie", cookie.getName() + "=" + cookie.getValue() + "; SameSite=Strict");
    }

    public void good_case_2(HttpServletResponse response) {
        // ok: java-cookie-httponly
        Cookie cookie = new Cookie("authToken", "xyz789");
        cookie.setMaxAge(3600);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
        response.setHeader("Set-Cookie", cookie.getName() + "=" + cookie.getValue() + "; SameSite=Strict");
    }

    public void good_case_3(JakartaHttpServletResponse response) {
        // ok: java-cookie-httponly
        JakartaCookie cookie = new JakartaCookie("userId", "12345");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/api");
        response.addCookie(cookie);
        response.setHeader("Set-Cookie", cookie.getName() + "=" + cookie.getValue() + "; SameSite=Strict");
    }

    @RestController
    public class GoodCookieController1 {
        @GetMapping("/good-cookie-4")
        public void good_case_4(HttpServletResponse response) {
            // ok: java-cookie-httponly
            Cookie userCookie = new Cookie("preferences", "theme=dark");
            userCookie.setMaxAge(604800); // 1 week
            userCookie.setDomain("example.com");
            userCookie.setHttpOnly(true);
            userCookie.setSecure(true);
            response.addCookie(userCookie);
            response.setHeader("Set-Cookie", userCookie.getName() + "=" + userCookie.getValue() + "; SameSite=Strict");
        }
    }

    public ResponseEntity<String> good_case_5() {
        // ok: java-cookie-httponly
        ResponseCookie cookie = ResponseCookie.from("rememberMe", "true")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .build();
        
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body("Secure cookie set");
    }

    public void good_case_6(HttpServletResponse response) {
        // ok: java-cookie-httponly
        Cookie cookie = new Cookie("cart", "item1,item2");
        cookie.setMaxAge(86400);
        cookie.setPath("/shop");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        response.addCookie(cookie);
        response.setHeader("Set-Cookie", cookie.getName() + "=" + cookie.getValue() + "; SameSite=Strict");
    }

    public ResponseEntity<String> good_case_7() {
        // ok: java-cookie-httponly
        ResponseCookie cookie = ResponseCookie.from("tracking", "visitor123")
                .maxAge(2592000) // 30 days
                .path("/")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .build();
        
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body("Secure cookie set");
    }

    public void good_case_8(HttpServletResponse response) {
        // ok: java-cookie-httponly
        Cookie cookie = new Cookie("language", "en-US");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        response.addCookie(cookie);
        response.setHeader("Set-Cookie", cookie.getName() + "=" + cookie.getValue() + "; SameSite=Strict");
    }

    public void good_case_9(HttpServletResponse response, String token) {
        if (token != null && !token.isEmpty()) {
            // ok: java-cookie-httponly
            Cookie authCookie = new Cookie("authToken", token);
            authCookie.setMaxAge(-1); // Session cookie
            authCookie.setPath("/");
            authCookie.setSecure(true);
            authCookie.setHttpOnly(true);
            response.addCookie(authCookie);
            response.setHeader("Set-Cookie", authCookie.getName() + "=" + authCookie.getValue() + "; SameSite=Strict");
        }
    }

    public void good_case_10(HttpServletResponse response) {
        // ok: java-cookie-httponly
        String cookieValue = "sessionId=abc123; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict";
        response.setHeader("Set-Cookie", cookieValue);
    }

    public ResponseEntity<String> good_case_11() {
        // ok: java-cookie-httponly
        ResponseCookie cookie = ResponseCookie.from("sessionId", "abc123")
                .sameSite("Strict")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .build();
        
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body("Secure session cookie set");
    }

    public void good_case_12(HttpServletResponse response) {
        // ok: java-cookie-httponly
        Cookie cookie1 = new Cookie("preference1", "value1");
        Cookie cookie2 = new Cookie("preference2", "value2");
        
        cookie1.setHttpOnly(true);
        cookie1.setSecure(true);
        
        cookie2.setHttpOnly(true);
        cookie2.setSecure(true);
        
        response.addCookie(cookie1);
        response.addCookie(cookie2);
        
        response.setHeader("Set-Cookie", cookie1.getName() + "=" + cookie1.getValue() + "; SameSite=Strict");
        response.setHeader("Set-Cookie", cookie2.getName() + "=" + cookie2.getValue() + "; SameSite=Strict");
    }

    public void good_case_13(HttpServletResponse response) {
        for (String userData : getUserDataList()) {
            // ok: java-cookie-httponly
            Cookie userCookie = new Cookie("userData", userData);
            userCookie.setPath("/");
            userCookie.setHttpOnly(true);
            userCookie.setSecure(true);
            response.addCookie(userCookie);
            response.setHeader("Set-Cookie", userCookie.getName() + "=" + userCookie.getValue() + "; SameSite=Strict");
        }
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) {
        // ok: java-cookie-httponly
        // Example of updating cookies securely
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("sessionId".equals(cookie.getName())) {
                    cookie.setValue(generateNewSessionId());
                    cookie.setHttpOnly(true);
                    cookie.setSecure(true);
                    response.addCookie(cookie);
                    response.setHeader("Set-Cookie", cookie.getName() + "=" + cookie.getValue() + "; SameSite=Strict");
                }
            }
        }
    }

    public ResponseEntity<String> good_case_15() {
        // ok: java-cookie-httponly
        String cookieString = "sessionId=xyz789; Path=/; HttpOnly; Secure; SameSite=Strict";
        
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookieString)
                .body("Secure cookie set");
    }

    // Helper methods
    private boolean isSecureEnvironment() {
        return true; // Simplified for example
    }

    private String[] getUserDataList() {
        return new String[]{"data1", "data2"}; // Simplified for example
    }

    private String generateNewSessionId() {
        return "new-session-id-" + System.currentTimeMillis(); // Simplified for example
    }
}
// {/fact}