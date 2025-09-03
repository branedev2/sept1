import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import java.util.logging.Level;
import org.apache.log4j.Priority;
import ch.qos.logback.classic.LoggerContext;
import org.jboss.logging.BasicLogger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.tinylog.TaggedLogger;
import org.pmw.tinylog.Configurator;
import org.apache.logging.log4j.message.FormattedMessage;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.HashMap;
import org.apache.http.client.methods.HttpGet;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import retrofit2.Retrofit;
import retrofit2.http.GET;
import retrofit2.http.Query;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import org.springframework.cloud.openfeign.FeignClient;
import feign.RequestLine;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.HttpRequest;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.apache.commons.lang3.StringUtils;

// Security Issue: Using String.format(), string concatenation, or StringBuilder in logging statements can lead to unnecessary string formatting

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    Logger logger = LoggerFactory.getLogger(getClass());
    String username = request.getParameter("username");
    String action = request.getParameter("action");
    
    if (logger.isDebugEnabled()) {
        // ruleid: java-avoid-string-formatting-in-logging
        logger.debug(String.format("User %s performed action %s", username, action));
    }
}

public void bad_case_2(HttpServletRequest request) {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    String ipAddress = request.getRemoteAddr();
    String requestPath = request.getRequestURI();
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.info("Request from IP: " + ipAddress + " accessing path: " + requestPath);
}

public void bad_case_3(HttpServletRequest request) {
    Log logger = LogFactory.getLog(getClass());
    String sessionId = request.getSession().getId();
    String userAgent = request.getHeader("User-Agent");
    
    StringBuilder sb = new StringBuilder();
    sb.append("Session ID: ");
    sb.append(sessionId);
    sb.append(", User-Agent: ");
    sb.append(userAgent);
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.warn(sb.toString());
}

public void bad_case_4(HttpServletRequest request) {
    java.util.logging.Logger logger = java.util.logging.Logger.getLogger(getClass().getName());
    String contentType = request.getContentType();
    int contentLength = request.getContentLength();
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.log(Level.SEVERE, "Invalid content: type=" + contentType + ", length=" + contentLength);
}

public void bad_case_5() {
    org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(getClass());
    HttpGet request = new HttpGet("https://api.example.com/data");
    String endpoint = request.getURI().toString();
    String method = request.getMethod();
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.debug(String.format("Sending %s request to %s", method, endpoint));
}

@RestController
public void bad_case_6(@RequestParam String query) {
    LoggerContext loggerContext = new LoggerContext();
    ch.qos.logback.classic.Logger logger = loggerContext.getLogger(getClass());
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.error("Processing search query: " + query + " at timestamp: " + System.currentTimeMillis());
}

public void bad_case_7(APIGatewayProxyRequestEvent event) {
    org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(getClass());
    String path = event.getPath();
    Map<String, String> headers = event.getHeaders();
    
    StringBuilder logMessage = new StringBuilder();
    logMessage.append("Lambda invoked with path: ");
    logMessage.append(path);
    logMessage.append(", headers count: ");
    logMessage.append(headers.size());
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.info(logMessage.toString());
}

public void bad_case_8(HttpRequest<?> request) {
    org.tinylog.Logger logger = org.tinylog.Logger.getLogger();
    String clientId = request.getParameters().get("client_id");
    String scope = request.getParameters().get("scope");
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.warn(String.format("OAuth request with client_id=%s and scope=%s", clientId, scope));
}

public void bad_case_9(Request request) {
    org.pmw.tinylog.Logger logger = org.pmw.tinylog.Logger.getLogger();
    String method = request.getMethod();
    String url = request.getRequestURI().toString();
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.info("Jetty handling " + method + " request for " + url);
}

public void bad_case_10(RoutingContext ctx) {
    Logger logger = LoggerFactory.getLogger(getClass());
    String param = ctx.request().getParam("id");
    String token = ctx.request().getHeader("Authorization");
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.debug(String.format("Vertx request with id=%s and auth token length=%d", 
                              param, token != null ? token.length() : 0));
}

public void bad_case_11(io.micronaut.http.HttpRequest<?> request) {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    String origin = request.getHeaders().get("Origin");
    String referer = request.getHeaders().get("Referer");
    
    StringBuilder sb = new StringBuilder();
    sb.append("CORS request from origin: ");
    sb.append(origin);
    sb.append(" with referer: ");
    sb.append(referer);
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.info(sb.toString());
}

public void bad_case_12(Context ctx) {
    Logger logger = LoggerFactory.getLogger(getClass());
    String body = ctx.body();
    String contentType = ctx.contentType();
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.warn("Javalin received request with body size: " + body.length() + 
               " and content type: " + contentType);
}

public void bad_case_13(okhttp3.Request request) {
    Log logger = LogFactory.getLog(getClass());
    String url = request.url().toString();
    String method = request.method();
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.info(String.format("OkHttp sending %s request to %s", method, url));
}

public void bad_case_14(HttpServletRequest request) {
    TaggedLogger logger = org.tinylog.TaggedLogger.getLogger("security");
    String username = request.getParameter("username");
    String ipAddress = request.getRemoteAddr();
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.error("Failed login attempt for user: " + username + " from IP: " + ipAddress);
}

public void bad_case_15(feign.Request request) {
    Logger logger = LoggerFactory.getLogger(getClass());
    String url = request.url();
    Map<String, Collection<String>> headers = request.headers();
    
    StringBuilder sb = new StringBuilder();
    sb.append("Feign client request to ");
    sb.append(url);
    sb.append(" with ");
    sb.append(headers.size());
    sb.append(" headers");
    
    // ruleid: java-avoid-string-formatting-in-logging
    logger.debug(sb.toString());
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    Logger logger = LoggerFactory.getLogger(getClass());
    String username = request.getParameter("username");
    String action = request.getParameter("action");
    
    // ok: java-avoid-string-formatting-in-logging
    logger.debug("User {} performed action {}", username, action);
}

public void good_case_2(HttpServletRequest request) {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    String ipAddress = request.getRemoteAddr();
    String requestPath = request.getRequestURI();
    
    // ok: java-avoid-string-formatting-in-logging
    logger.info("Request from IP: {} accessing path: {}", ipAddress, requestPath);
}

public void good_case_3(HttpServletRequest request) {
    Log logger = LogFactory.getLog(getClass());
    String sessionId = request.getSession().getId();
    String userAgent = request.getHeader("User-Agent");
    
    // Apache Commons Logging doesn't have built-in parameterized logging,
    // but we can use isEnabledFor to avoid unnecessary string formatting
    if (logger.isWarnEnabled()) {
        // ok: java-avoid-string-formatting-in-logging
        logger.warn("Session ID: " + sessionId + ", User-Agent: " + userAgent);
    }
}

public void good_case_4(HttpServletRequest request) {
    java.util.logging.Logger logger = java.util.logging.Logger.getLogger(getClass().getName());
    String contentType = request.getContentType();
    int contentLength = request.getContentLength();
    
    // JUL doesn't have built-in parameterized logging, but we can use isLoggable
    if (logger.isLoggable(Level.SEVERE)) {
        // ok: java-avoid-string-formatting-in-logging
        logger.log(Level.SEVERE, "Invalid content: type=" + contentType + ", length=" + contentLength);
    }
}

public void good_case_5() {
    org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(getClass());
    HttpGet request = new HttpGet("https://api.example.com/data");
    String endpoint = request.getURI().toString();
    String method = request.getMethod();
    
    // Log4j 1.x doesn't have built-in parameterized logging, but we can use isEnabledFor
    if (logger.isEnabledFor(Priority.DEBUG)) {
        // ok: java-avoid-string-formatting-in-logging
        logger.debug("Sending " + method + " request to " + endpoint);
    }
}

@RestController
public void good_case_6(@RequestParam String query) {
    LoggerContext loggerContext = new LoggerContext();
    ch.qos.logback.classic.Logger logger = loggerContext.getLogger(getClass());
    
    // ok: java-avoid-string-formatting-in-logging
    logger.error("Processing search query: {} at timestamp: {}", query, System.currentTimeMillis());
}

public void good_case_7(APIGatewayProxyRequestEvent event) {
    org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(getClass());
    String path = event.getPath();
    Map<String, String> headers = event.getHeaders();
    
    // ok: java-avoid-string-formatting-in-logging
    logger.info("Lambda invoked with path: {}, headers count: {}", path, headers.size());
}

public void good_case_8(HttpRequest<?> request) {
    org.tinylog.Logger logger = org.tinylog.Logger.getLogger();
    String clientId = request.getParameters().get("client_id");
    String scope = request.getParameters().get("scope");
    
    // ok: java-avoid-string-formatting-in-logging
    logger.warn("OAuth request with client_id={} and scope={}", clientId, scope);
}

public void good_case_9(Request request) {
    org.pmw.tinylog.Logger logger = org.pmw.tinylog.Logger.getLogger();
    String method = request.getMethod();
    String url = request.getRequestURI().toString();
    
    // TinyLog 1.x doesn't have built-in parameterized logging
    if (org.pmw.tinylog.Logger.isInfoEnabled()) {
        // ok: java-avoid-string-formatting-in-logging
        logger.info("Jetty handling " + method + " request for " + url);
    }
}

public void good_case_10(RoutingContext ctx) {
    Logger logger = LoggerFactory.getLogger(getClass());
    String param = ctx.request().getParam("id");
    String token = ctx.request().getHeader("Authorization");
    
    // ok: java-avoid-string-formatting-in-logging
    logger.debug("Vertx request with id={} and auth token length={}", 
                param, token != null ? token.length() : 0);
}

public void good_case_11(io.micronaut.http.HttpRequest<?> request) {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    String origin = request.getHeaders().get("Origin");
    String referer = request.getHeaders().get("Referer");
    
    // ok: java-avoid-string-formatting-in-logging
    logger.info("CORS request from origin: {} with referer: {}", origin, referer);
}

public void good_case_12(Context ctx) {
    Logger logger = LoggerFactory.getLogger(getClass());
    String body = ctx.body();
    String contentType = ctx.contentType();
    
    // ok: java-avoid-string-formatting-in-logging
    logger.warn("Javalin received request with body size: {} and content type: {}", 
               body.length(), contentType);
}

public void good_case_13(okhttp3.Request request) {
    Log logger = LogFactory.getLog(getClass());
    String url = request.url().toString();
    String method = request.method();
    
    // Apache Commons Logging doesn't have built-in parameterized logging
    if (logger.isInfoEnabled()) {
        // ok: java-avoid-string-formatting-in-logging
        logger.info("OkHttp sending " + method + " request to " + url);
    }
}

public void good_case_14(HttpServletRequest request) {
    TaggedLogger logger = org.tinylog.TaggedLogger.getLogger("security");
    String username = request.getParameter("username");
    String ipAddress = request.getRemoteAddr();
    
    // ok: java-avoid-string-formatting-in-logging
    logger.error("Failed login attempt for user: {} from IP: {}", username, ipAddress);
}

public void good_case_15(feign.Request request) {
    Logger logger = LoggerFactory.getLogger(getClass());
    String url = request.url();
    Map<String, Collection<String>> headers = request.headers();
    
    // ok: java-avoid-string-formatting-in-logging
    logger.debug("Feign client request to {} with {} headers", url, headers.size());
}