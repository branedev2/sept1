import java.io.IOException;
import java.util.logging.Logger;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ch.qos.logback.classic.Logger;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.logging.Logger;
import org.tinylog.Logger;
import org.pmw.tinylog.Logger;
import org.apache.log4j.Logger;
import com.google.cloud.logging.LoggingOptions;
import com.google.cloud.logging.Logging;
import com.google.cloud.logging.LogEntry;
import com.google.cloud.logging.Severity;
import com.google.cloud.logging.LogEntry.Builder;
import io.sentry.Sentry;
import io.sentry.SentryEvent;
import io.sentry.protocol.Message;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.SpanBuilder;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.context.Scope;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.methods.CloseableHttpResponse;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.microsoft.applicationinsights.TelemetryClient;
import com.microsoft.applicationinsights.telemetry.ExceptionTelemetry;
import com.newrelic.api.agent.NewRelic;
import com.rollbar.notifier.Rollbar;
import com.rollbar.notifier.config.Config;
import com.rollbar.notifier.config.ConfigBuilder;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.retry.backoff.FixedBackOffPolicy;
import org.springframework.retry.policy.SimpleRetryPolicy;

// Security Issue: Failing to log exception stack traces can lead to loss of critical debugging information

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Java Util Logging (JUL) - Missing stack trace
    Logger logger = Logger.getLogger(getClass().getName());
    
    try {
        String param = request.getParameter("input");
        Integer.parseInt(param);
    } catch (NumberFormatException e) {
        // ruleid: java-log-exception-with-stack-trace
        logger.log(Level.SEVERE, "Error parsing input: " + e.getMessage());
    }
}

public void bad_case_2(HttpServletRequest request) {
    // Log4j2 - Missing stack trace
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    
    try {
        String header = request.getHeader("Content-Type");
        if (header.contains("json")) {
            // Process JSON
        }
    } catch (NullPointerException e) {
        // ruleid: java-log-exception-with-stack-trace
        logger.error("Null content type: {}", e.getMessage());
    }
}

public void bad_case_3(HttpServletRequest request) {
    // SLF4J - Missing stack trace
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    
    try {
        String[] values = request.getParameterValues("items");
        processItems(values[0]);
    } catch (ArrayIndexOutOfBoundsException e) {
        // ruleid: java-log-exception-with-stack-trace
        logger.error("No items provided: {}", e.getMessage());
    }
}

public void bad_case_4(HttpServletRequest request) {
    // Logback - Missing stack trace
    ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(getClass());
    
    try {
        String path = request.getPathInfo();
        if (path.startsWith("/admin")) {
            // Admin functionality
        }
    } catch (NullPointerException e) {
        // ruleid: java-log-exception-with-stack-trace
        logger.error("Path error: " + e.getMessage());
    }
}

public void bad_case_5(HttpServletRequest request) {
    // Apache Commons Logging - Missing stack trace
    Log logger = LogFactory.getLog(getClass());
    
    try {
        String method = request.getMethod();
        if (!method.equals("GET")) {
            throw new IllegalArgumentException("Only GET supported");
        }
    } catch (IllegalArgumentException e) {
        // ruleid: java-log-exception-with-stack-trace
        logger.error("Method not supported: " + e.getMessage());
    }
}

public void bad_case_6(HttpServletRequest request) {
    // JBoss Logging - Missing stack trace
    org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(getClass());
    
    try {
        String auth = request.getHeader("Authorization");
        validateAuth(auth);
    } catch (SecurityException e) {
        // ruleid: java-log-exception-with-stack-trace
        logger.error("Auth failed: " + e.getMessage());
    }
}

public void bad_case_7(HttpServletRequest request) {
    // TinyLog 2 - Missing stack trace
    try {
        String param = request.getParameter("action");
        if (param == null) {
            throw new IllegalStateException("Action required");
        }
    } catch (IllegalStateException e) {
        // ruleid: java-log-exception-with-stack-trace
        org.tinylog.Logger.error("Action error: {}", e.getMessage());
    }
}

public void bad_case_8(HttpServletRequest request) {
    // TinyLog 1.x - Missing stack trace
    try {
        String value = request.getParameter("config");
        processConfig(value);
    } catch (Exception e) {
        // ruleid: java-log-exception-with-stack-trace
        org.pmw.tinylog.Logger.error("Config error: {}", e.getMessage());
    }
}

public void bad_case_9(HttpServletRequest request) {
    // Log4j 1.x - Missing stack trace
    org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(getClass());
    
    try {
        String data = request.getParameter("data");
        processData(data.trim());
    } catch (NullPointerException e) {
        // ruleid: java-log-exception-with-stack-trace
        logger.error("Data processing error: " + e.getMessage());
    }
}

public void bad_case_10(HttpServletRequest request) {
    // Google Cloud Logging - Missing stack trace
    LoggingOptions options = LoggingOptions.getDefaultInstance();
    
    try (Logging logging = options.getService()) {
        String userId = request.getParameter("userId");
        if (userId == null) {
            throw new IllegalArgumentException("User ID is required");
        }
    } catch (IllegalArgumentException e) {
        // ruleid: java-log-exception-with-stack-trace
        LogEntry entry = LogEntry.newBuilder()
            .setSeverity(Severity.ERROR)
            .setTextPayload("User ID error: " + e.getMessage())
            .build();
        // Log entry without stack trace
    }
}

public void bad_case_11(HttpServletRequest request) {
    // Sentry - Missing stack trace in custom event
    try {
        String token = request.getHeader("X-API-Token");
        validateToken(token);
    } catch (SecurityException e) {
        // ruleid: java-log-exception-with-stack-trace
        SentryEvent event = new SentryEvent();
        Message message = new Message();
        message.setMessage("Token validation error: " + e.getMessage());
        event.setMessage(message);
        Sentry.captureEvent(event);
        // No exception captured, only message
    }
}

public void bad_case_12(HttpServletRequest request) {
    // OpenTelemetry - Missing exception in span
    Tracer tracer = getTracer();
    SpanBuilder spanBuilder = tracer.spanBuilder("processRequest");
    Span span = spanBuilder.startSpan();
    
    try (Scope scope = span.makeCurrent()) {
        String data = request.getParameter("payload");
        processPayload(data);
    } catch (Exception e) {
        // ruleid: java-log-exception-with-stack-trace
        span.setAttribute("error", true);
        span.setAttribute("error.message", e.getMessage());
        // Missing recordException() call
    } finally {
        span.end();
    }
}

public void bad_case_13(HttpServletRequest request) {
    // Application Insights - Missing stack trace
    TelemetryClient telemetryClient = new TelemetryClient();
    
    try {
        String query = request.getQueryString();
        processQuery(query);
    } catch (Exception e) {
        // ruleid: java-log-exception-with-stack-trace
        telemetryClient.trackTrace("Query processing error: " + e.getMessage());
        // Should use trackException instead
    }
}

public void bad_case_14(HttpServletRequest request) {
    // New Relic - Missing stack trace
    try {
        String contentType = request.getContentType();
        if (contentType == null) {
            throw new IllegalArgumentException("Content type required");
        }
    } catch (IllegalArgumentException e) {
        // ruleid: java-log-exception-with-stack-trace
        NewRelic.noticeError("Content type error: " + e.getMessage());
        // Missing the exception parameter
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Rollbar - Missing stack trace
    Config config = ConfigBuilder.withAccessToken("access-token").build();
    Rollbar rollbar = Rollbar.init(config);
    
    try {
        String id = request.getParameter("id");
        if (id == null) {
            throw new IllegalArgumentException("ID is required");
        }
    } catch (IllegalArgumentException e) {
        // ruleid: java-log-exception-with-stack-trace
        rollbar.info("ID validation error: " + e.getMessage());
        // Should use rollbar.error(e, "message") instead
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Java Util Logging (JUL) - With stack trace
    Logger logger = Logger.getLogger(getClass().getName());
    
    try {
        String param = request.getParameter("input");
        Integer.parseInt(param);
    } catch (NumberFormatException e) {
        // ok: java-log-exception-with-stack-trace
        logger.log(Level.SEVERE, "Error parsing input", e);
    }
}

public void good_case_2(HttpServletRequest request) {
    // Log4j2 - With stack trace
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    
    try {
        String header = request.getHeader("Content-Type");
        if (header.contains("json")) {
            // Process JSON
        }
    } catch (NullPointerException e) {
        // ok: java-log-exception-with-stack-trace
        logger.error("Null content type", e);
    }
}

public void good_case_3(HttpServletRequest request) {
    // SLF4J - With stack trace
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    
    try {
        String[] values = request.getParameterValues("items");
        processItems(values[0]);
    } catch (ArrayIndexOutOfBoundsException e) {
        // ok: java-log-exception-with-stack-trace
        logger.error("No items provided", e);
    }
}

public void good_case_4(HttpServletRequest request) {
    // Logback - With stack trace
    ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(getClass());
    
    try {
        String path = request.getPathInfo();
        if (path.startsWith("/admin")) {
            // Admin functionality
        }
    } catch (NullPointerException e) {
        // ok: java-log-exception-with-stack-trace
        logger.error("Path error", e);
    }
}

public void good_case_5(HttpServletRequest request) {
    // Apache Commons Logging - With stack trace
    Log logger = LogFactory.getLog(getClass());
    
    try {
        String method = request.getMethod();
        if (!method.equals("GET")) {
            throw new IllegalArgumentException("Only GET supported");
        }
    } catch (IllegalArgumentException e) {
        // ok: java-log-exception-with-stack-trace
        logger.error("Method not supported", e);
    }
}

public void good_case_6(HttpServletRequest request) {
    // JBoss Logging - With stack trace
    org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(getClass());
    
    try {
        String auth = request.getHeader("Authorization");
        validateAuth(auth);
    } catch (SecurityException e) {
        // ok: java-log-exception-with-stack-trace
        logger.error("Auth failed", e);
    }
}

public void good_case_7(HttpServletRequest request) {
    // TinyLog 2 - With stack trace
    try {
        String param = request.getParameter("action");
        if (param == null) {
            throw new IllegalStateException("Action required");
        }
    } catch (IllegalStateException e) {
        // ok: java-log-exception-with-stack-trace
        org.tinylog.Logger.error(e, "Action error");
    }
}

public void good_case_8(HttpServletRequest request) {
    // TinyLog 1.x - With stack trace
    try {
        String value = request.getParameter("config");
        processConfig(value);
    } catch (Exception e) {
        // ok: java-log-exception-with-stack-trace
        org.pmw.tinylog.Logger.error(e, "Config error");
    }
}

public void good_case_9(HttpServletRequest request) {
    // Log4j 1.x - With stack trace
    org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(getClass());
    
    try {
        String data = request.getParameter("data");
        processData(data.trim());
    } catch (NullPointerException e) {
        // ok: java-log-exception-with-stack-trace
        logger.error("Data processing error", e);
    }
}

public void good_case_10(HttpServletRequest request) {
    // Google Cloud Logging - With stack trace
    LoggingOptions options = LoggingOptions.getDefaultInstance();
    
    try (Logging logging = options.getService()) {
        String userId = request.getParameter("userId");
        if (userId == null) {
            throw new IllegalArgumentException("User ID is required");
        }
    } catch (IllegalArgumentException e) {
        // ok: java-log-exception-with-stack-trace
        LogEntry entry = LogEntry.newBuilder()
            .setSeverity(Severity.ERROR)
            .setTextPayload("User ID error: " + e.getMessage())
            .addLabel("stacktrace", getStackTraceAsString(e))
            .build();
        // Log entry with stack trace
    }
}

public void good_case_11(HttpServletRequest request) {
    // Sentry - With stack trace
    try {
        String token = request.getHeader("X-API-Token");
        validateToken(token);
    } catch (SecurityException e) {
        // ok: java-log-exception-with-stack-trace
        Sentry.captureException(e);
    }
}

public void good_case_12(HttpServletRequest request) {
    // OpenTelemetry - With exception in span
    Tracer tracer = getTracer();
    SpanBuilder spanBuilder = tracer.spanBuilder("processRequest");
    Span span = spanBuilder.startSpan();
    
    try (Scope scope = span.makeCurrent()) {
        String data = request.getParameter("payload");
        processPayload(data);
    } catch (Exception e) {
        // ok: java-log-exception-with-stack-trace
        span.recordException(e);
        span.setStatus(StatusCode.ERROR, e.getMessage());
    } finally {
        span.end();
    }
}

public void good_case_13(HttpServletRequest request) {
    // Application Insights - With stack trace
    TelemetryClient telemetryClient = new TelemetryClient();
    
    try {
        String query = request.getQueryString();
        processQuery(query);
    } catch (Exception e) {
        // ok: java-log-exception-with-stack-trace
        ExceptionTelemetry telemetry = new ExceptionTelemetry(e);
        telemetryClient.trackException(telemetry);
    }
}

public void good_case_14(HttpServletRequest request) {
    // New Relic - With stack trace
    try {
        String contentType = request.getContentType();
        if (contentType == null) {
            throw new IllegalArgumentException("Content type required");
        }
    } catch (IllegalArgumentException e) {
        // ok: java-log-exception-with-stack-trace
        NewRelic.noticeError(e);
    }
}

public void good_case_15(HttpServletRequest request) {
    // Rollbar - With stack trace
    Config config = ConfigBuilder.withAccessToken("access-token").build();
    Rollbar rollbar = Rollbar.init(config);
    
    try {
        String id = request.getParameter("id");
        if (id == null) {
            throw new IllegalArgumentException("ID is required");
        }
    } catch (IllegalArgumentException e) {
        // ok: java-log-exception-with-stack-trace
        rollbar.error(e, "ID validation error");
    }
}

// Helper methods to make the examples compile
private void processItems(String item) {}
private void validateAuth(String auth) {}
private void processConfig(String config) {}
private void processData(String data) {}
private void processPayload(String payload) {}
private void processQuery(String query) {}
private void validateToken(String token) {}
private Tracer getTracer() { return null; }
private String getStackTraceAsString(Exception e) { return ""; }