import java.io.IOException;
import java.util.logging.Logger;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.slf4j.LoggerFactory;
import ch.qos.logback.classic.Logger;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.logging.Logger;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import java.util.regex.Pattern;
import org.owasp.encoder.Encode;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import spark.Request;
import spark.Response;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.javalin.http.Context;
import ratpack.handling.Context;
import ratpack.http.Request;
import org.apache.commons.text.StringEscapeUtils;

// Security Issue: Log Injection Vulnerability (CWE-117, CWE-93)

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    Logger logger = Logger.getLogger(getClass().getName());
    String username = request.getParameter("username");
    
    // ruleid: java-log-injection
    logger.info("User login attempt: " + username);
}

public void bad_case_2(HttpServletRequest request) {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    String ipAddress = request.getHeader("X-Forwarded-For");
    
    // ruleid: java-log-injection
    logger.error("Failed login attempt from IP: {}", ipAddress);
}

public void bad_case_3(HttpServletRequest request) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    String searchQuery = request.getParameter("q");
    
    // ruleid: java-log-injection
    logger.warn("Search query executed: " + searchQuery);
}

@RestController
public void bad_case_4(@RequestParam String email) {
    ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(getClass());
    
    // ruleid: java-log-injection
    logger.debug("Newsletter subscription request from: {}", email);
}

@Path("/api")
public void bad_case_5(@QueryParam("action") String action) {
    org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(getClass());
    
    // ruleid: java-log-injection
    logger.fatal("Critical action performed: " + action);
}

public void bad_case_6(HttpServletRequest request) {
    org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(getClass());
    String userAgent = request.getHeader("User-Agent");
    
    // ruleid: java-log-injection
    logger.info("Request from user agent: " + userAgent);
}

public void bad_case_7(spark.Request request, spark.Response response) {
    Log log = LogFactory.getLog(getClass());
    String referrer = request.headers("Referer");
    
    // ruleid: java-log-injection
    log.warn("Request referred from: " + referrer);
}

public class bad_case_8 implements HttpHandler {
    private static final java.util.logging.Logger logger = java.util.logging.Logger.getLogger("ServerHandler");
    
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String requestMethod = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        
        // ruleid: java-log-injection
        logger.log(Level.INFO, "Received {0} request for path: {1}", new Object[]{requestMethod, path});
    }
}

public void bad_case_9(RoutingContext routingContext) {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    HttpServerRequest request = routingContext.request();
    String contentType = request.getHeader("Content-Type");
    
    // ruleid: java-log-injection
    logger.info("Processing request with content type: " + contentType);
}

@Controller("/users")
public void bad_case_10(HttpRequest<?> request) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    String authHeader = request.getHeaders().get("Authorization");
    
    // ruleid: java-log-injection
    logger.info("Auth attempt with token: {}", authHeader);
}

public void bad_case_11(io.javalin.http.Context ctx) {
    Logger logger = Logger.getLogger(getClass().getName());
    String requestId = ctx.header("X-Request-ID");
    
    // ruleid: java-log-injection
    logger.severe("Processing request ID: " + requestId);
}

public void bad_case_12(ratpack.handling.Context ctx) {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    ratpack.http.Request request = ctx.getRequest();
    String acceptHeader = request.getHeaders().get("Accept");
    
    // ruleid: java-log-injection
    logger.info("Client accepts: " + acceptHeader);
}

@RestController
public void bad_case_13(@RequestBody String payload) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    
    // ruleid: java-log-injection
    logger.info("Received payload: {}", payload);
}

public void bad_case_14(HttpServletRequest request) {
    org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(getClass());
    String sessionId = request.getSession().getId();
    
    // ruleid: java-log-injection
    MDC.put("sessionId", sessionId);
    logger.info("Session started");
}

public void bad_case_15(HttpServletRequest request, HttpServletResponse response) {
    org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(getClass());
    String errorMessage = request.getParameter("error");
    
    // ruleid: java-log-injection
    logger.error("Error reported by client: " + errorMessage);
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    Logger logger = Logger.getLogger(getClass().getName());
    String username = request.getParameter("username");
    // Sanitize by removing CRLF characters
    username = username.replaceAll("[\\r\\n]", "");
    
    // ok: java-log-injection
    logger.info("User login attempt: " + username);
}

public void good_case_2(HttpServletRequest request) {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    String ipAddress = request.getHeader("X-Forwarded-For");
    // Use Pattern to validate IP format and reject invalid input
    if (ipAddress != null && Pattern.matches("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$", ipAddress)) {
        // ok: java-log-injection
        logger.error("Failed login attempt from IP: {}", ipAddress);
    } else {
        logger.error("Failed login attempt from invalid IP");
    }
}

public void good_case_3(HttpServletRequest request) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    String searchQuery = request.getParameter("q");
    // Use OWASP encoder to sanitize input
    String sanitizedQuery = Encode.forJava(searchQuery);
    
    // ok: java-log-injection
    logger.warn("Search query executed: " + sanitizedQuery);
}

@RestController
public void good_case_4(@RequestParam String email) {
    ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(getClass());
    // Validate email format before logging
    if (email != null && email.matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$")) {
        String sanitizedEmail = email.replaceAll("[\\r\\n]", "");
        
        // ok: java-log-injection
        logger.debug("Newsletter subscription request from: {}", sanitizedEmail);
    } else {
        logger.debug("Invalid email format received");
    }
}

@Path("/api")
public void good_case_5(@QueryParam("action") String action) {
    org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(getClass());
    // Whitelist approach - only allow specific actions
    List<String> allowedActions = Arrays.asList("create", "read", "update", "delete");
    String safeAction = allowedActions.contains(action) ? action : "INVALID";
    
    // ok: java-log-injection
    logger.fatal("Critical action performed: " + safeAction);
}

public void good_case_6(HttpServletRequest request) {
    org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(getClass());
    String userAgent = request.getHeader("User-Agent");
    // Sanitize by removing control characters
    String safeUserAgent = userAgent.replaceAll("[\\p{Cntrl}]", "");
    
    // ok: java-log-injection
    logger.info("Request from user agent: " + safeUserAgent);
}

public void good_case_7(spark.Request request, spark.Response response) {
    Log log = LogFactory.getLog(getClass());
    String referrer = request.headers("Referer");
    // Use Apache Commons Text to escape
    String safeReferrer = StringEscapeUtils.escapeJava(referrer);
    
    // ok: java-log-injection
    log.warn("Request referred from: " + safeReferrer);
}

public class good_case_8 implements HttpHandler {
    private static final java.util.logging.Logger logger = java.util.logging.Logger.getLogger("ServerHandler");
    
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String requestMethod = exchange.getRequestMethod();
        // Validate HTTP method is standard
        if (!Arrays.asList("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS").contains(requestMethod)) {
            requestMethod = "UNKNOWN";
        }
        
        String path = exchange.getRequestURI().getPath();
        // Sanitize path by removing control characters
        path = path.replaceAll("[\\p{Cntrl}]", "");
        
        // ok: java-log-injection
        logger.log(Level.INFO, "Received {0} request for path: {1}", new Object[]{requestMethod, path});
    }
}

public void good_case_9(RoutingContext routingContext) {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    HttpServerRequest request = routingContext.request();
    String contentType = request.getHeader("Content-Type");
    // Validate content type format
    if (contentType != null && contentType.matches("^[a-zA-Z0-9/\\-+.]+$")) {
        // ok: java-log-injection
        logger.info("Processing request with content type: " + contentType);
    } else {
        logger.info("Processing request with invalid content type");
    }
}

@Controller("/users")
public void good_case_10(HttpRequest<?> request) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    String authHeader = request.getHeaders().get("Authorization");
    // Mask sensitive information in auth header
    String maskedAuth = null;
    if (authHeader != null && authHeader.startsWith("Bearer ")) {
        maskedAuth = "Bearer " + authHeader.substring(7, 12) + "...";
    } else {
        maskedAuth = "Invalid-Auth-Format";
    }
    
    // ok: java-log-injection
    logger.info("Auth attempt with token: {}", maskedAuth);
}

public void good_case_11(io.javalin.http.Context ctx) {
    Logger logger = Logger.getLogger(getClass().getName());
    String requestId = ctx.header("X-Request-ID");
    // Validate UUID format
    if (requestId != null && requestId.matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) {
        // ok: java-log-injection
        logger.severe("Processing request ID: " + requestId);
    } else {
        logger.severe("Processing request with invalid request ID");
    }
}

public void good_case_12(ratpack.handling.Context ctx) {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    ratpack.http.Request request = ctx.getRequest();
    String acceptHeader = request.getHeaders().get("Accept");
    // Sanitize header
    String safeHeader = acceptHeader != null ? 
        acceptHeader.replaceAll("[\\r\\n]", "").replaceAll("[\\p{Cntrl}]", "") : "null";
    
    // ok: java-log-injection
    logger.info("Client accepts: " + safeHeader);
}

@RestController
public void good_case_13(@RequestBody String payload) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    // Truncate large payloads to prevent log flooding
    String truncatedPayload = payload.length() > 100 ? 
        payload.substring(0, 100).replaceAll("[\\r\\n]", "") + "..." : 
        payload.replaceAll("[\\r\\n]", "");
    
    // ok: java-log-injection
    logger.info("Received payload: {}", truncatedPayload);
}

public void good_case_14(HttpServletRequest request) {
    org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(getClass());
    String sessionId = request.getSession().getId();
    // Only log part of the session ID for security
    String partialSessionId = sessionId.substring(0, 5) + "...";
    
    // ok: java-log-injection
    MDC.put("sessionId", partialSessionId);
    logger.info("Session started");
}

public void good_case_15(HttpServletRequest request, HttpServletResponse response) {
    org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(getClass());
    String errorMessage = request.getParameter("error");
    // Use a predefined list of error messages
    Map<String, String> errorCodes = new HashMap<>();
    errorCodes.put("404", "Resource not found");
    errorCodes.put("403", "Access denied");
    errorCodes.put("500", "Internal server error");
    
    String safeErrorMessage = errorCodes.getOrDefault(errorMessage, "Unknown error");
    
    // ok: java-log-injection
    logger.error("Error reported by client: " + safeErrorMessage);
}