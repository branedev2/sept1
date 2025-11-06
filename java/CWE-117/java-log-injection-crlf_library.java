import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.util.Strings;
import org.slf4j.LoggerFactory;
import ch.qos.logback.classic.Logger as LogbackLogger;
import org.jboss.logging.Logger as JBossLogger;
import java.util.logging.Logger as JavaLogger;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Logger as Log4jLegacyLogger;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.Context;
import io.vertx.core.logging.LoggerFactory as VertxLoggerFactory;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.HttpHeaders;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.HttpRequest;
import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;
import io.vertx.ext.web.RoutingContext;
import ratpack.handling.Context as RatpackContext;
import ratpack.handling.Handler;
import spark.Request;
import spark.Response;
import spark.Route as SparkRoute;
import com.google.common.net.UrlEscapers;
import org.apache.commons.lang3.StringUtils;
import java.util.regex.Pattern;

// Security Issue: Log Injection through CRLF in log4j and other logging frameworks

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    Logger logger = LogManager.getLogger(getClass());
    String username = request.getParameter("username");
    
    // ruleid: java-log-injection-crlf
    logger.info("User login attempt: " + username);
}

public void bad_case_2(@RequestParam String query, @RequestHeader("User-Agent") String userAgent) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    
    // ruleid: java-log-injection-crlf
    logger.info("Search query from {}: {}", userAgent, query);
}

@Path("/api")
public void bad_case_3(@QueryParam("message") String message, @Context HttpHeaders headers) {
    LogbackLogger logger = (LogbackLogger) LoggerFactory.getLogger(getClass());
    String clientIp = headers.getHeaderString("X-Forwarded-For");
    
    // ruleid: java-log-injection-crlf
    logger.warn("Client {} sent message: {}", clientIp, message);
}

@Controller("/admin")
public void bad_case_4(HttpRequest<?> request) {
    JBossLogger logger = JBossLogger.getLogger(getClass());
    String action = request.getParameters().get("action");
    
    // ruleid: java-log-injection-crlf
    logger.error("Admin action attempted: " + action);
}

@RouteBase(path = "/events")
public void bad_case_5(RoutingContext context) {
    io.vertx.core.logging.Logger logger = VertxLoggerFactory.getLogger(getClass().getName());
    String eventData = context.request().getParam("data");
    
    // ruleid: java-log-injection-crlf
    logger.info("Event received: " + eventData);
}

public void bad_case_6(Request request, Response response) {
    JavaLogger logger = JavaLogger.getLogger(getClass().getName());
    String referrer = request.headers("Referer");
    
    // ruleid: java-log-injection-crlf
    logger.info("Request referred from: " + referrer);
}

public void bad_case_7(HttpServletRequest request) {
    Log logger = LogFactory.getLog(getClass());
    String comments = request.getParameter("comments");
    
    // ruleid: java-log-injection-crlf
    logger.debug("User feedback: " + comments);
}

public void bad_case_8(RatpackContext ctx) {
    Log4jLegacyLogger logger = Log4jLegacyLogger.getLogger(getClass());
    String payload = ctx.getRequest().getBody().getText();
    
    // ruleid: java-log-injection-crlf
    logger.warn("Received payload: " + payload);
}

public void bad_case_9(Context context) {
    LambdaLogger logger = context.getLogger();
    String input = context.getClientContext().getCustom().get("userInput");
    
    // ruleid: java-log-injection-crlf
    logger.log("Processing user input: " + input);
}

public void bad_case_10(HttpServletRequest request) {
    org.apache.juli.logging.Log logger = org.apache.juli.logging.LogFactory.getLog(getClass());
    String sessionId = request.getParameter("sessionId");
    
    // ruleid: java-log-injection-crlf
    logger.error("Invalid session: " + sessionId);
}

public void bad_case_11(HttpRequest<?> request) {
    org.tinylog.Logger logger = org.tinylog.Logger.getLogger(getClass());
    String searchTerm = request.getParameters().get("q");
    
    // ruleid: java-log-injection-crlf
    logger.info("Search term: {}", searchTerm);
}

public void bad_case_12(HttpServletRequest request) {
    com.netflix.logging.BaseLogger logger = new com.netflix.logging.BaseLogger("SecurityAudit");
    String authToken = request.getHeader("Authorization");
    
    // ruleid: java-log-injection-crlf
    logger.info("Auth attempt with token: " + authToken);
}

public void bad_case_13(spark.Request request) {
    org.pmw.tinylog.Logger logger = org.pmw.tinylog.Logger.getInstance(getClass());
    String ipAddress = request.ip();
    String payload = request.body();
    
    // ruleid: java-log-injection-crlf
    logger.error("Request from {} with payload: {}", ipAddress, payload);
}

public void bad_case_14(HttpServletRequest request) {
    com.google.common.flogger.FluentLogger logger = com.google.common.flogger.FluentLogger.forEnclosingClass();
    String requestPath = request.getRequestURI();
    
    // ruleid: java-log-injection-crlf
    logger.atInfo().log("Accessed path: %s", requestPath);
}

public void bad_case_15(HttpServletRequest request) {
    org.jboss.logmanager.Logger logger = org.jboss.logmanager.Logger.getLogger(getClass().getName());
    String formData = request.getParameter("formData");
    
    // ruleid: java-log-injection-crlf
    logger.log(org.jboss.logmanager.Level.INFO, "Form submission: " + formData);
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    Logger logger = LogManager.getLogger(getClass());
    String username = request.getParameter("username");
    // Sanitize by replacing CRLF characters
    String sanitizedUsername = username.replace("\r", "\\r").replace("\n", "\\n");
    
    // ok: java-log-injection-crlf
    logger.info("User login attempt: " + sanitizedUsername);
}

public void good_case_2(@RequestParam String query, @RequestHeader("User-Agent") String userAgent) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    // Use StringEscapeUtils to escape control characters
    String safeQuery = StringEscapeUtils.escapeJava(query);
    String safeUserAgent = StringEscapeUtils.escapeJava(userAgent);
    
    // ok: java-log-injection-crlf
    logger.info("Search query from {}: {}", safeUserAgent, safeQuery);
}

@Path("/api")
public void good_case_3(@QueryParam("message") String message, @Context HttpHeaders headers) {
    LogbackLogger logger = (LogbackLogger) LoggerFactory.getLogger(getClass());
    String clientIp = headers.getHeaderString("X-Forwarded-For");
    // Use OWASP Encoder to sanitize input
    String safeMessage = Encode.forJava(message);
    
    // ok: java-log-injection-crlf
    logger.warn("Client {} sent message: {}", clientIp, safeMessage);
}

@Controller("/admin")
public void good_case_4(HttpRequest<?> request) {
    JBossLogger logger = JBossLogger.getLogger(getClass());
    String action = request.getParameters().get("action");
    // Use regex to remove control characters
    String safeAction = action.replaceAll("[\\r\\n]", "");
    
    // ok: java-log-injection-crlf
    logger.error("Admin action attempted: " + safeAction);
}

@RouteBase(path = "/events")
public void good_case_5(RoutingContext context) {
    io.vertx.core.logging.Logger logger = VertxLoggerFactory.getLogger(getClass().getName());
    String eventData = context.request().getParam("data");
    // Use Pattern to filter out CRLF
    Pattern pattern = Pattern.compile("[\\r\\n]");
    String safeEventData = pattern.matcher(eventData).replaceAll("");
    
    // ok: java-log-injection-crlf
    logger.info("Event received: " + safeEventData);
}

public void good_case_6(Request request, Response response) {
    JavaLogger logger = JavaLogger.getLogger(getClass().getName());
    String referrer = request.headers("Referer");
    // Use StringUtils to remove control chars
    String safeReferrer = StringUtils.replaceChars(referrer, "\r\n", "");
    
    // ok: java-log-injection-crlf
    logger.info("Request referred from: " + safeReferrer);
}

public void good_case_7(HttpServletRequest request) {
    Log logger = LogFactory.getLog(getClass());
    String comments = request.getParameter("comments");
    // Use custom sanitization method
    String safeComments = sanitizeLogInput(comments);
    
    // ok: java-log-injection-crlf
    logger.debug("User feedback: " + safeComments);
}

private String sanitizeLogInput(String input) {
    if (input == null) {
        return "";
    }
    return input.replace('\n', '_').replace('\r', '_');
}

public void good_case_8(RatpackContext ctx) {
    Log4jLegacyLogger logger = Log4jLegacyLogger.getLogger(getClass());
    String payload = ctx.getRequest().getBody().getText();
    // Use URL escaper for sanitization
    String safePayload = UrlEscapers.urlPathSegmentEscaper().escape(payload);
    
    // ok: java-log-injection-crlf
    logger.warn("Received payload: " + safePayload);
}

public void good_case_9(Context context) {
    LambdaLogger logger = context.getLogger();
    String input = context.getClientContext().getCustom().get("userInput");
    // Use log4j's built-in protection by using parameterized logging
    
    // ok: java-log-injection-crlf
    logger.log(String.format("Processing user input: %s", Strings.escapeControlChars(input)));
}

public void good_case_10(HttpServletRequest request) {
    org.apache.juli.logging.Log logger = org.apache.juli.logging.LogFactory.getLog(getClass());
    String sessionId = request.getParameter("sessionId");
    // Remove all non-alphanumeric characters for session IDs
    String safeSessionId = sessionId.replaceAll("[^a-zA-Z0-9]", "");
    
    // ok: java-log-injection-crlf
    logger.error("Invalid session: " + safeSessionId);
}

public void good_case_11(HttpRequest<?> request) {
    org.tinylog.Logger logger = org.tinylog.Logger.getLogger(getClass());
    String searchTerm = request.getParameters().get("q");
    // Use StringBuilder to manually escape control chars
    StringBuilder sb = new StringBuilder();
    for (char c : searchTerm.toCharArray()) {
        if (c == '\r' || c == '\n') {
            sb.append("\\").append((int)c);
        } else {
            sb.append(c);
        }
    }
    
    // ok: java-log-injection-crlf
    logger.info("Search term: {}", sb.toString());
}

public void good_case_12(HttpServletRequest request) {
    com.netflix.logging.BaseLogger logger = new com.netflix.logging.BaseLogger("SecurityAudit");
    String authToken = request.getHeader("Authorization");
    // Mask sensitive data and remove control chars
    String maskedToken = "REDAC_REDACTED_TWILIO_ID-" + authToken.hashCode();
    String safeToken = maskedToken.replaceAll("[\\r\\n]", "");
    
    // ok: java-log-injection-crlf
    logger.info("Auth attempt with token: " + safeToken);
}

public void good_case_13(spark.Request request) {
    org.pmw.tinylog.Logger logger = org.pmw.tinylog.Logger.getInstance(getClass());
    String ipAddress = request.ip();
    String payload = request.body();
    // Use Apache Commons Text for sanitization
    String safePayload = org.apache.commons.text.StringEscapeUtils.escapeJava(payload);
    
    // ok: java-log-injection-crlf
    logger.error("Request from {} with payload: {}", ipAddress, safePayload);
}

public void good_case_14(HttpServletRequest request) {
    com.google.common.flogger.FluentLogger logger = com.google.common.flogger.FluentLogger.forEnclosingClass();
    String requestPath = request.getRequestURI();
    // Use Guava's CharMatcher to remove control chars
    String safeRequestPath = com.google.common.base.CharMatcher.javaIsoControl().removeFrom(requestPath);
    
    // ok: java-log-injection-crlf
    logger.atInfo().log("Accessed path: %s", safeRequestPath);
}

public void good_case_15(HttpServletRequest request) {
    org.jboss.logmanager.Logger logger = org.jboss.logmanager.Logger.getLogger(getClass().getName());
    String formData = request.getParameter("formData");
    // Use a whitelist approach - only allow specific characters
    String safeFormData = formData.replaceAll("[^a-zA-Z0-9\\s.,;:!?()\\[\\]{}'\"-]", "_");
    
    // ok: java-log-injection-crlf
    logger.log(org.jboss.logmanager.Level.INFO, "Form submission: " + safeFormData);
}