import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringEscapeUtils;
import org.owasp.encoder.Encode;
import org.apache.commons.text.StringEscapeUtils;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class CRLFInjectionExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
    protected void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter
        String userInput = request.getParameter("page");
        
        // Using unsanitized user input in a header
        // ruleid: java-crlf-injection
        response.setHeader("Location", userInput);
    }

    protected void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter
        String userInput = request.getParameter("username");
        
        // Using unsanitized user input in a cookie
        Cookie cookie = new Cookie("username", userInput);
        // ruleid: java-crlf-injection
        response.addCookie(cookie);
    }

    protected void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request header
        String userAgent = request.getHeader("User-Agent");
        
        // Using unsanitized header value in another header
        // ruleid: java-crlf-injection
        response.setHeader("X-User-Agent", userAgent);
    }

    protected void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter with string concatenation
        String userId = request.getParameter("id");
        String headerValue = "user-" + userId;
        
        // Using unsanitized user input in a header
        // ruleid: java-crlf-injection
        response.addHeader("X-User-ID", headerValue);
    }

    protected void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting multiple user inputs and combining them
        String firstName = request.getParameter("firstName");
        String lastName = request.getParameter("lastName");
        String fullName = firstName + " " + lastName;
        
        // Using unsanitized combined user input in a cookie
        Cookie cookie = new Cookie("fullName", fullName);
        // ruleid: java-crlf-injection
        response.addCookie(cookie);
    }

    protected void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from a cookie
        Cookie[] cookies = request.getCookies();
        String userValue = "";
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("userPreference")) {
                    userValue = cookie.getValue();
                    break;
                }
            }
        }
        
        // Using unsanitized cookie value in a header
        // ruleid: java-crlf-injection
        response.setHeader("X-User-Preference", userValue);
    }

    protected void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter
        String language = request.getParameter("lang");
        
        if (language != null && !language.isEmpty()) {
            // Using unsanitized user input in a header with conditional logic
            // ruleid: java-crlf-injection
            response.setHeader("Content-Language", language);
        } else {
            response.setHeader("Content-Language", "en-US");
        }
    }

    protected void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter and transforming it
        String theme = request.getParameter("theme");
        String themeValue = theme.toLowerCase();
        
        // Using transformed but still unsanitized user input in a cookie
        Cookie cookie = new Cookie("theme", themeValue);
        // ruleid: java-crlf-injection
        response.addCookie(cookie);
    }

    protected void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from multiple sources
        String referer = request.getHeader("Referer");
        String customReferer = request.getParameter("ref");
        
        // Using the custom referer if provided, otherwise using the header
        String finalReferer = (customReferer != null && !customReferer.isEmpty()) ? customReferer : referer;
        
        // Using unsanitized user input in a header
        // ruleid: java-crlf-injection
        response.setHeader("X-Referer", finalReferer);
    }

    protected void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter
        String sessionId = request.getParameter("sessionId");
        
        // Using unsanitized user input in a cookie with additional attributes
        Cookie cookie = new Cookie("sessionId", sessionId);
        cookie.setMaxAge(3600);
        cookie.setSecure(true);
        // ruleid: java-crlf-injection
        response.addCookie(cookie);
    }

    protected void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter
        String redirectUrl = request.getParameter("redirect");
        
        // Using unsanitized user input in a Location header for redirection
        // ruleid: java-crlf-injection
        response.setHeader("Location", redirectUrl);
        response.setStatus(HttpServletResponse.SC_FOUND);
    }

    protected void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter with string formatting
        String userId = request.getParameter("userId");
        String formattedValue = String.format("user-%s-session", userId);
        
        // Using unsanitized formatted user input in a header
        // ruleid: java-crlf-injection
        response.setHeader("X-Session-Info", formattedValue);
    }

    protected void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from a request attribute that might have been set by another component
        String userRole = (String) request.getAttribute("userRole");
        
        if (userRole == null) {
            userRole = request.getParameter("role");
        }
        
        // Using unsanitized user input in a header
        // ruleid: java-crlf-injection
        response.setHeader("X-User-Role", userRole);
    }

    protected void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter
        String trackingId = request.getParameter("trackingId");
        
        // Using unsanitized user input in multiple cookies
        Cookie cookie1 = new Cookie("trackingId", trackingId);
        Cookie cookie2 = new Cookie("trackingIdBackup", trackingId);
        
        // ruleid: java-crlf-injection
        response.addCookie(cookie1);
        // ruleid: java-crlf-injection
        response.addCookie(cookie2);
    }

    protected void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter and using StringBuilder
        String customHeader = request.getParameter("customHeader");
        StringBuilder headerValue = new StringBuilder();
        headerValue.append("custom-").append(customHeader).append("-value");
        
        // Using unsanitized user input in a header via StringBuilder
        // ruleid: java-crlf-injection
        response.setHeader("X-Custom", headerValue.toString());
    }

    // True Negative Examples (Safe Code)

    protected void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter
        String userInput = request.getParameter("page");
        
        // Sanitizing user input before using it in a header
        String sanitizedInput = URLEncoder.encode(userInput, StandardCharsets.UTF_8.toString());
        // ok: java-crlf-injection
        response.setHeader("Location", sanitizedInput);
    }

    protected void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter
        String userInput = request.getParameter("username");
        
        // Sanitizing user input before using it in a cookie
        String sanitizedInput = Encode.forJava(userInput);
        Cookie cookie = new Cookie("username", sanitizedInput);
        // ok: java-crlf-injection
        response.addCookie(cookie);
    }

    protected void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request header
        String userAgent = request.getHeader("User-Agent");
        
        // Sanitizing header value before using it in another header
        String sanitizedAgent = userAgent.replaceAll("[\\r\\n]", "");
        // ok: java-crlf-injection
        response.setHeader("X-User-Agent", sanitizedAgent);
    }

    protected void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter with string concatenation
        String userId = request.getParameter("id");
        
        // Sanitizing user input before concatenation and using in a header
        String sanitizedId = userId.replaceAll("[^a-zA-Z0-9]", "");
        String headerValue = "user-" + sanitizedId;
        
        // ok: java-crlf-injection
        response.addHeader("X-User-ID", headerValue);
    }

    protected void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting multiple user inputs and combining them
        String firstName = request.getParameter("firstName");
        String lastName = request.getParameter("lastName");
        
        // Sanitizing user inputs before combining and using in a cookie
        String sanitizedFirstName = Encode.forJava(firstName);
        String sanitizedLastName = Encode.forJava(lastName);
        String fullName = sanitizedFirstName + " " + sanitizedLastName;
        
        Cookie cookie = new Cookie("fullName", fullName);
        // ok: java-crlf-injection
        response.addCookie(cookie);
    }

    protected void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from a cookie
        Cookie[] cookies = request.getCookies();
        String userValue = "";
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("userPreference")) {
                    userValue = cookie.getValue();
                    break;
                }
            }
        }
        
        // Sanitizing cookie value before using it in a header
        String sanitizedValue = URLEncoder.encode(userValue, StandardCharsets.UTF_8.toString());
        // ok: java-crlf-injection
        response.setHeader("X-User-Preference", sanitizedValue);
    }

    protected void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter
        String language = request.getParameter("lang");
        
        if (language != null && !language.isEmpty()) {
            // Validating against a whitelist of allowed values
            if (language.matches("^(en-US|fr-FR|es-ES|de-DE)$")) {
                // ok: java-crlf-injection
                response.setHeader("Content-Language", language);
            } else {
                response.setHeader("Content-Language", "en-US");
            }
        } else {
            response.setHeader("Content-Language", "en-US");
        }
    }

    protected void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter and transforming it
        String theme = request.getParameter("theme");
        
        // Sanitizing user input before transformation and using in a cookie
        String sanitizedTheme = theme.replaceAll("[\\r\\n]", "");
        String themeValue = sanitizedTheme.toLowerCase();
        
        Cookie cookie = new Cookie("theme", themeValue);
        // ok: java-crlf-injection
        response.addCookie(cookie);
    }

    protected void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from multiple sources
        String referer = request.getHeader("Referer");
        String customReferer = request.getParameter("ref");
        
        // Using the custom referer if provided, otherwise using the header
        String unsanitizedReferer = (customReferer != null && !customReferer.isEmpty()) ? customReferer : referer;
        
        // Sanitizing before using in a header
        String sanitizedReferer = StringEscapeUtils.escapeHtml4(unsanitizedReferer);
        // ok: java-crlf-injection
        response.setHeader("X-Referer", sanitizedReferer);
    }

    protected void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter
        String sessionId = request.getParameter("sessionId");
        
        // Sanitizing user input before using in a cookie with additional attributes
        String sanitizedSessionId = sessionId.replaceAll("[^a-zA-Z0-9-]", "");
        Cookie cookie = new Cookie("sessionId", sanitizedSessionId);
        cookie.setMaxAge(3600);
        cookie.setSecure(true);
        // ok: java-crlf-injection
        response.addCookie(cookie);
    }

    protected void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter
        String redirectUrl = request.getParameter("redirect");
        
        // Validating URL against a whitelist of allowed domains
        if (redirectUrl != null && (redirectUrl.startsWith("https://example.com/") || 
                                   redirectUrl.startsWith("https://subdomain.example.com/"))) {
            // ok: java-crlf-injection
            response.setHeader("Location", redirectUrl);
            response.setStatus(HttpServletResponse.SC_FOUND);
        } else {
            response.setHeader("Location", "https://example.com/default");
            response.setStatus(HttpServletResponse.SC_FOUND);
        }
    }

    protected void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter with string formatting
        String userId = request.getParameter("userId");
        
        // Sanitizing user input before formatting and using in a header
        String sanitizedUserId = userId.replaceAll("[^a-zA-Z0-9]", "");
        String formattedValue = String.format("user-%s-session", sanitizedUserId);
        
        // ok: java-crlf-injection
        response.setHeader("X-Session-Info", formattedValue);
    }

    protected void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from a request attribute that might have been set by another component
        String userRole = (String) request.getAttribute("userRole");
        
        if (userRole == null) {
            userRole = request.getParameter("role");
        }
        
        // Validating against a whitelist of allowed roles
        String validatedRole;
        if (userRole != null && (userRole.equals("admin") || userRole.equals("user") || userRole.equals("guest"))) {
            validatedRole = userRole;
        } else {
            validatedRole = "guest";
        }
        
        // ok: java-crlf-injection
        response.setHeader("X-User-Role", validatedRole);
    }

    protected void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter
        String trackingId = request.getParameter("trackingId");
        
        // Sanitizing user input before using in multiple cookies
        String sanitizedTrackingId = Encode.forJava(trackingId);
        
        Cookie cookie1 = new Cookie("trackingId", sanitizedTrackingId);
        Cookie cookie2 = new Cookie("trackingIdBackup", sanitizedTrackingId);
        
        // ok: java-crlf-injection
        response.addCookie(cookie1);
        // ok: java-crlf-injection
        response.addCookie(cookie2);
    }

    protected void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Getting user input from request parameter and using StringBuilder
        String customHeader = request.getParameter("customHeader");
        
        // Sanitizing user input before using in StringBuilder
        String sanitizedHeader = customHeader.replaceAll("[\\r\\n]", "");
        
        StringBuilder headerValue = new StringBuilder();
        headerValue.append("custom-").append(sanitizedHeader).append("-value");
        
        // ok: java-crlf-injection
        response.setHeader("X-Custom", headerValue.toString());
    }
}
// {/fact}