import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletResponse as JakartaResponse;
import jakarta.servlet.http.Cookie as JakartaCookie;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.http.ResponseCookie;
import org.springframework.http.HttpCookie;
import java.net.HttpCookie as JavaNetHttpCookie;

@Controller
public class InsecureCookieExamples {

    // True Positive Examples (Insecure Cookies)

// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @GetMapping("/bad_case_1")
    public void bad_case_1(HttpServletResponse response) {
        // ruleid: java-insecure-cookie
        Cookie cookie = new Cookie("sessionId", "abc123");
        cookie.setMaxAge(86400);
        response.addCookie(cookie);
    }

    @GetMapping("/bad_case_2")
    public void bad_case_2(HttpServletResponse response) {
        // ruleid: java-insecure-cookie
        Cookie cookie = new Cookie("authToken", "xyz789");
        cookie.setPath("/");
        cookie.setMaxAge(3600);
        cookie.setHttpOnly(true); // HttpOnly is set but Secure is missing
        response.addCookie(cookie);
    }

    @GetMapping("/bad_case_3")
    public void bad_case_3(HttpServletResponse response) {
        // ruleid: java-insecure-cookie
        Cookie cookie = new Cookie("userData", "user123");
        cookie.setMaxAge(86400);
        cookie.setSecure(false); // Explicitly set to false
        response.addCookie(cookie);
    }

    @GetMapping("/bad_case_4")
    public void bad_case_4(JakartaResponse response) {
        // ruleid: java-insecure-cookie
        JakartaCookie cookie = new JakartaCookie("rememberMe", "true");
        cookie.setMaxAge(604800); // 7 days
        response.addCookie(cookie);
    }

    @GetMapping("/bad_case_5")
    public void bad_case_5(HttpServletResponse response) {
        String userId = "user456";
        // ruleid: java-insecure-cookie
        Cookie cookie = new Cookie("userId", userId);
        if (userId.length() > 5) {
            cookie.setHttpOnly(true);
        }
        response.addCookie(cookie);
    }

    @GetMapping("/bad_case_6")
    public void bad_case_6(HttpServletResponse response) {
        // ruleid: java-insecure-cookie
        Cookie[] cookies = new Cookie[2];
        cookies[0] = new Cookie("preference", "darkMode");
        cookies[1] = new Cookie("language", "en-US");
        
        for (Cookie cookie : cookies) {
            cookie.setMaxAge(30 * 24 * 60 * 60); // 30 days
            response.addCookie(cookie);
        }
    }

    @GetMapping("/bad_case_7")
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) {
        String theme = request.getParameter("theme");
        if (theme != null && !theme.isEmpty()) {
            // ruleid: java-insecure-cookie
            Cookie cookie = new Cookie("theme", theme);
            cookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
            response.addCookie(cookie);
        }
    }

    @GetMapping("/bad_case_8")
    public void bad_case_8(HttpServletResponse response) {
        // ruleid: java-insecure-cookie
        ResponseCookie cookie = ResponseCookie.from("apiToken", "token123")
            .maxAge(3600)
            .httpOnly(true)
            .path("/")
            .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    @GetMapping("/bad_case_9")
    public void bad_case_9(HttpServletResponse response) {
        try {
            // ruleid: java-insecure-cookie
            JavaNetHttpCookie cookie = new JavaNetHttpCookie("sessionData", "data123");
            response.addHeader("Set-Cookie", cookie.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/bad_case_10")
    public void bad_case_10(HttpServletResponse response) {
        // ruleid: java-insecure-cookie
        Cookie cookie = new Cookie("trackingId", "track123");
        cookie.setMaxAge(-1); // Session cookie
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    @GetMapping("/bad_case_11")
    public void bad_case_11(HttpServletResponse response) {
        String cookieValue = generateRandomValue();
        // ruleid: java-insecure-cookie
        Cookie cookie = new Cookie("csrfToken", cookieValue);
        cookie.setMaxAge(1800); // 30 minutes
        response.addCookie(cookie);
    }

    @GetMapping("/bad_case_12")
    public void bad_case_12(HttpServletResponse response) {
        // ruleid: java-insecure-cookie
        Cookie cookie = new Cookie("cartId", "cart123");
        if (isProduction()) {
            cookie.setDomain(".example.com");
        }
        response.addCookie(cookie);
    }

    @GetMapping("/bad_case_13")
    public void bad_case_13(HttpServletResponse response, HttpSession session) {
        // ruleid: java-insecure-cookie
        Cookie cookie = new Cookie("JSESSIONID", session.getId());
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }

    @GetMapping("/bad_case_14")
    public void bad_case_14(HttpServletResponse response) {
        // ruleid: java-insecure-cookie
        String headerValue = "authId=auth123; Path=/; HttpOnly; Max-Age=3600";
        response.setHeader("Set-Cookie", headerValue);
    }

    @GetMapping("/bad_case_15")
    public void bad_case_15(HttpServletResponse response) {
        // ruleid: java-insecure-cookie
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from("analyticsId", "analytics123");
        builder.maxAge(2592000); // 30 days
        builder.path("/");
        ResponseCookie cookie = builder.build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    // True Negative Examples (Secure Cookies)

    @GetMapping("/good_case_1")
    public void good_case_1(HttpServletResponse response) {
        // ok: java-insecure-cookie
        Cookie cookie = new Cookie("sessionId", "abc123");
        cookie.setMaxAge(86400);
        cookie.setSecure(true);
        response.addCookie(cookie);
    }

    @GetMapping("/good_case_2")
    public void good_case_2(HttpServletResponse response) {
        // ok: java-insecure-cookie
        Cookie cookie = new Cookie("authToken", "xyz789");
        cookie.setPath("/");
        cookie.setMaxAge(3600);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        response.addCookie(cookie);
    }

    @GetMapping("/good_case_3")
    public void good_case_3(JakartaResponse response) {
        // ok: java-insecure-cookie
        JakartaCookie cookie = new JakartaCookie("userData", "user123");
        cookie.setMaxAge(86400);
        cookie.setSecure(true);
        response.addCookie(cookie);
    }

    @GetMapping("/good_case_4")
    public void good_case_4(HttpServletResponse response) {
        // ok: java-insecure-cookie
        Cookie cookie = new Cookie("rememberMe", "true");
        cookie.setMaxAge(604800); // 7 days
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }

    @GetMapping("/good_case_5")
    public void good_case_5(HttpServletResponse response) {
        String userId = "user456";
        // ok: java-insecure-cookie
        Cookie cookie = new Cookie("userId", userId);
        cookie.setSecure(true);
        if (userId.length() > 5) {
            cookie.setHttpOnly(true);
        }
        response.addCookie(cookie);
    }

    @GetMapping("/good_case_6")
    public void good_case_6(HttpServletResponse response) {
        // ok: java-insecure-cookie
        Cookie[] cookies = new Cookie[2];
        cookies[0] = new Cookie("preference", "darkMode");
        cookies[1] = new Cookie("language", "en-US");
        
        for (Cookie cookie : cookies) {
            cookie.setMaxAge(30 * 24 * 60 * 60); // 30 days
            cookie.setSecure(true);
            response.addCookie(cookie);
        }
    }

    @GetMapping("/good_case_7")
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) {
        String theme = request.getParameter("theme");
        if (theme != null && !theme.isEmpty()) {
            // ok: java-insecure-cookie
            Cookie cookie = new Cookie("theme", theme);
            cookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
            cookie.setSecure(true);
            response.addCookie(cookie);
        }
    }

    @GetMapping("/good_case_8")
    public void good_case_8(HttpServletResponse response) {
        // ok: java-insecure-cookie
        ResponseCookie cookie = ResponseCookie.from("apiToken", "token123")
            .maxAge(3600)
            .httpOnly(true)
            .secure(true)
            .path("/")
            .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    @GetMapping("/good_case_9")
    public void good_case_9(HttpServletResponse response) {
        try {
            // ok: java-insecure-cookie
            JavaNetHttpCookie cookie = new JavaNetHttpCookie("sessionData", "data123");
            cookie.setSecure(true);
            response.addHeader("Set-Cookie", cookie.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/good_case_10")
    public void good_case_10(HttpServletResponse response) {
        // ok: java-insecure-cookie
        Cookie cookie = new Cookie("trackingId", "track123");
        cookie.setMaxAge(-1); // Session cookie
        cookie.setPath("/");
        cookie.setSecure(true);
        response.addCookie(cookie);
    }

    @GetMapping("/good_case_11")
    public void good_case_11(HttpServletResponse response) {
        String cookieValue = generateRandomValue();
        // ok: java-insecure-cookie
        Cookie cookie = new Cookie("csrfToken", cookieValue);
        cookie.setMaxAge(1800); // 30 minutes
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }

    @GetMapping("/good_case_12")
    public void good_case_12(HttpServletResponse response) {
        // ok: java-insecure-cookie
        String headerValue = "authId=auth123; Path=/; HttpOnly; Secure; Max-Age=3600";
        response.setHeader("Set-Cookie", headerValue);
    }

    @GetMapping("/good_case_13")
    public void good_case_13(HttpServletResponse response, HttpSession session) {
        // ok: java-insecure-cookie
        Cookie cookie = new Cookie("JSESSIONID", session.getId());
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        response.addCookie(cookie);
    }

    @GetMapping("/good_case_14")
    public void good_case_14(HttpServletResponse response) {
        // ok: java-insecure-cookie
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from("analyticsId", "analytics123");
        builder.maxAge(2592000); // 30 days
        builder.path("/");
        builder.secure(true);
        ResponseCookie cookie = builder.build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    @GetMapping("/good_case_15")
    public void good_case_15(HttpServletResponse response) {
        boolean isSecureEnvironment = true;
        // ok: java-insecure-cookie
        Cookie cookie = new Cookie("cartId", "cart123");
        if (isProduction()) {
            cookie.setDomain(".example.com");
        }
        cookie.setSecure(isSecureEnvironment);
        response.addCookie(cookie);
    }

    // Helper methods
    private String generateRandomValue() {
        return "random" + System.currentTimeMillis();
    }
    
    private boolean isProduction() {
        return true;
    }
}
// {/fact}