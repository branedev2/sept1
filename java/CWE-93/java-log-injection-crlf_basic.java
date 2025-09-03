package com.example.loginjectionsample;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.util.Strings;
import org.owasp.encoder.Encode;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import java.io.IOException;
import java.util.regex.Pattern;

public class LogInjectionExamples extends HttpServlet {
    private static final Logger logger = LogManager.getLogger(LogInjectionExamples.class);
    private static final Pattern NEWLINE_PATTERN = Pattern.compile("[\r\n]");

    // True positive examples (vulnerable code)

// {fact rule=file-injection@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        // ruleid: java-log-injection-crlf
        logger.info("User login attempt: " + username);
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        // ruleid: java-log-injection-crlf
        logger.warn("Suspicious activity from IP: {}", ipAddress);
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
        String userAgent = request.getHeader("User-Agent");
        String message = "Browser information: " + userAgent;
        // ruleid: java-log-injection-crlf
        logger.debug(message);
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                // ruleid: java-log-injection-crlf
                logger.info("Cookie name: {}, value: {}", cookie.getName(), cookie.getValue());
            }
        }
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) {
        String searchQuery = request.getParameter("q");
        StringBuilder logMessage = new StringBuilder();
        logMessage.append("Search query: ").append(searchQuery);
        // ruleid: java-log-injection-crlf
        logger.info(logMessage.toString());
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) {
        String referer = request.getHeader("Referer");
        if (referer != null) {
            // ruleid: java-log-injection-crlf
            logger.info("Request referred from: " + referer);
        } else {
            logger.info("No referer information");
        }
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String email = request.getParameter("email");
        try {
            // Some processing with email
            if (email.contains("@")) {
                // ruleid: java-log-injection-crlf
                logger.info("Processing request for email: " + email);
            }
        } catch (Exception e) {
            // ruleid: java-log-injection-crlf
            logger.error("Error processing email: " + email, e);
        }
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) {
        String action = request.getParameter("action");
        String item = request.getParameter("item");
        
        switch (action) {
            case "add":
                // ruleid: java-log-injection-crlf
                logger.info("Adding item: " + item);
                break;
            case "remove":
                // ruleid: java-log-injection-crlf
                logger.info("Removing item: " + item);
                break;
            default:
                // ruleid: java-log-injection-crlf
                logger.warn("Unknown action: " + action + " for item: " + item);
        }
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) {
        String sessionId = request.getRequestedSessionId();
        String username = request.getParameter("username");
        
        // ruleid: java-log-injection-crlf
        logger.info("Session {} accessed by user {}", sessionId, username);
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) {
        String[] selectedItems = request.getParameterValues("items");
        if (selectedItems != null) {
            for (String item : selectedItems) {
                // ruleid: java-log-injection-crlf
                logger.info("Selected item: " + item);
            }
        }
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) {
        String comments = request.getParameter("comments");
        if (comments != null && !comments.isEmpty()) {
            // ruleid: java-log-injection-crlf
            logger.info("User feedback received: {}", comments);
        }
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) {
        String language = request.getParameter("lang");
        String country = request.getParameter("country");
        
        // ruleid: java-log-injection-crlf
        logger.info("Locale settings - Language: {}, Country: {}", language, country);
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) {
        String errorCode = request.getParameter("error");
        if (errorCode != null) {
            String errorMessage = "Client reported error: " + errorCode;
            // ruleid: java-log-injection-crlf
            logger.error(errorMessage);
        }
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) {
        String query = request.getQueryString();
        // ruleid: java-log-injection-crlf
        logger.debug("Full query string: {}", query);
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            // ruleid: java-log-injection-crlf
            logger.trace("Authentication attempt with token: {}", authHeader.substring(7));
        }
    }

    // True negative examples (safe code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        // ok: java-log-injection-crlf
        logger.info("User login attempt: {}", username.replaceAll("[\r\n]", ""));
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        // ok: java-log-injection-crlf
        logger.warn("Suspicious activity from IP: {}", NEWLINE_PATTERN.matcher(ipAddress).replaceAll(""));
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
        String userAgent = request.getHeader("User-Agent");
        // ok: java-log-injection-crlf
        logger.debug("Browser information: {}", Encode.forJava(userAgent));
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                String sanitizedName = cookie.getName().replaceAll("[\r\n]", "");
                String sanitizedValue = cookie.getValue().replaceAll("[\r\n]", "");
                // ok: java-log-injection-crlf
                logger.info("Cookie name: {}, value: {}", sanitizedName, sanitizedValue);
            }
        }
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) {
        String searchQuery = request.getParameter("q");
        // ok: java-log-injection-crlf
        logger.info("Search query: {}", Strings.toRootLowerCase(searchQuery).replaceAll("[\r\n]", "_"));
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) {
        String referer = request.getHeader("Referer");
        if (referer != null) {
            // ok: java-log-injection-crlf
            logger.info("Request referred from: {}", sanitizeInput(referer));
        } else {
            logger.info("No referer information");
        }
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String email = request.getParameter("email");
        try {
            // Some processing with email
            if (email.contains("@")) {
                // ok: java-log-injection-crlf
                logger.info("Processing request for email: {}", email.replaceAll("[\r\n]", ""));
            }
        } catch (Exception e) {
            // ok: java-log-injection-crlf
            logger.error("Error processing email: " + sanitizeInput(email), e);
        }
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) {
        String action = request.getParameter("action");
        String item = request.getParameter("item");
        String sanitizedAction = sanitizeInput(action);
        String sanitizedItem = sanitizeInput(item);
        
        switch (action) {
            case "add":
                // ok: java-log-injection-crlf
                logger.info("Adding item: {}", sanitizedItem);
                break;
            case "remove":
                // ok: java-log-injection-crlf
                logger.info("Removing item: {}", sanitizedItem);
                break;
            default:
                // ok: java-log-injection-crlf
                logger.warn("Unknown action: {} for item: {}", sanitizedAction, sanitizedItem);
        }
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) {
        String sessionId = request.getRequestedSessionId();
        String username = request.getParameter("username");
        
        // Using constants or system-generated values is safe
        // ok: java-log-injection-crlf
        logger.info("Session {} accessed by user {}", sessionId, username.replaceAll("[\r\n]", ""));
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) {
        String[] selectedItems = request.getParameterValues("items");
        if (selectedItems != null) {
            for (String item : selectedItems) {
                // ok: java-log-injection-crlf
                logger.info("Selected item: {}", NEWLINE_PATTERN.matcher(item).replaceAll(""));
            }
        }
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) {
        String comments = request.getParameter("comments");
        if (comments != null && !comments.isEmpty()) {
            // ok: java-log-injection-crlf
            logger.info("User feedback received: {}", Encode.forJava(comments));
        }
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) {
        String language = request.getParameter("lang");
        String country = request.getParameter("country");
        
        // ok: java-log-injection-crlf
        logger.info("Locale settings - Language: {}, Country: {}", 
                    sanitizeInput(language), sanitizeInput(country));
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) {
        String errorCode = request.getParameter("error");
        if (errorCode != null) {
            // ok: java-log-injection-crlf
            logger.error("Client reported error: {}", errorCode.replaceAll("[^a-zA-Z0-9]", ""));
        }
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) {
        String query = request.getQueryString();
        // ok: java-log-injection-crlf
        logger.debug("Full query string: {}", query != null ? query.replaceAll("[\r\n]", "") : "null");
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            // ok: java-log-injection-crlf
            logger.trace("Authentication attempt with token: {}", maskSensitiveData(token));
        }
    }

    // Helper methods
    private String sanitizeInput(String input) {
        if (input == null) {
            return "null";
        }
        return input.replaceAll("[\r\n]", "");
    }

    private String maskSensitiveData(String data) {
        if (data == null) {
            return "null";
        }
        if (data.length() <= 4) {
            return "****";
        }
        return data.substring(0, 2) + "..." + data.substring(data.length() - 2);
    }
}
// {/fact}