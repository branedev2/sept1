import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import java.io.IOException;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import okhttp3.*;
import java.net.HttpURLConnection;
import java.net.URL;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.javalin.Javalin;
import io.javalin.http.Context;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import spark.Request;
import spark.Response;
import ratpack.server.RatpackServer;
import ratpack.handling.Context;
import ratpack.http.Response;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;
import org.apache.commons.lang3.StringUtils;
import com.google.common.net.HttpHeaders;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.ContainerResponse;
import javax.ws.rs.core.Response;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import org.apache.struts2.ServletActionContext;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.struts2.interceptor.ServletResponseAware;
import com.opensymphony.xwork2.ActionSupport;

// Security Issue: CRLF Injection in HTTP Headers and Cookies

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Using raw Servlet API to set a header with user input
    String userInput = request.getParameter("location");
    
    // ruleid: java-crlf-injection
    response.setHeader("Location", userInput);
}

public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Using raw Servlet API to set a cookie with user input
    String userValue = request.getParameter("value");
    Cookie cookie = new Cookie("sessionData", userValue);
    
    // ruleid: java-crlf-injection
    response.addCookie(cookie);
}

@RestController
public class bad_case_3 {
    @GetMapping("/redirect")
    public ResponseEntity<String> redirectUser(HttpServletRequest request) {
        // Using Spring's ResponseEntity to set headers
        String redirectUrl = request.getParameter("url");
        HttpHeaders headers = new HttpHeaders();
        
        // ruleid: java-crlf-injection
        headers.add("Location", redirectUrl);
        
        return new ResponseEntity<>("Redirecting...", headers, 302);
    }
}

public void bad_case_4() throws IOException {
    // Using Apache HttpClient to set headers with user input from URL parameters
    CloseableHttpClient httpClient = HttpClients.createDefault();
    String url = "https://example.com/api";
    HttpGet request = new HttpGet(url);
    
    // Simulating getting user input from an HTTP request
    String userAgent = getParameterFromRequest("user-agent");
    
    // ruleid: java-crlf-injection
    request.addHeader("User-Agent", userAgent);
    
    httpClient.execute(request);
}

public void bad_case_5() throws IOException {
    // Using OkHttp to set headers with user input
    OkHttpClient client = new OkHttpClient();
    
    // Simulating getting user input from an HTTP request
    String referer = getParameterFromRequest("referer");
    
    Request request = new Request.Builder()
        .url("https://example.com/api")
        // ruleid: java-crlf-injection
        .header("Referer", referer)
        .build();
    
    client.newCall(request).execute();
}

public void bad_case_6() throws IOException {
    // Using Java's HttpURLConnection to set headers with user input
    URL url = new URL("https://example.com/api");
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    
    // Simulating getting user input from an HTTP request
    String contentType = getParameterFromRequest("content-type");
    
    // ruleid: java-crlf-injection
    connection.setRequestProperty("Content-Type", contentType);
    
    connection.connect();
}

public void bad_case_7(Vertx vertx) {
    // Using Vert.x to set headers with user input
    Router router = Router.router(vertx);
    
    router.get("/api").handler(routingContext -> {
        HttpServerRequest request = routingContext.request();
        HttpServerResponse response = routingContext.response();
        
        String origin = request.getParam("origin");
        
        // ruleid: java-crlf-injection
        response.putHeader("Access-Control-Allow-Origin", origin);
        
        response.end("API response");
    });
}

public void bad_case_8() {
    // Using Javalin to set headers with user input
    Javalin app = Javalin.create().start(7000);
    
    app.get("/api", ctx -> {
        String cacheControl = ctx.queryParam("cache");
        
        // ruleid: java-crlf-injection
        ctx.header("Cache-Control", cacheControl);
        
        ctx.result("API response");
    });
}

public class bad_case_9 implements HttpHandler {
    // Using com.sun.net.httpserver to set headers with user input
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // Get query parameters
        String query = exchange.getRequestURI().getQuery();
        String contentType = extractParam(query, "type");
        
        // ruleid: java-crlf-injection
        exchange.getResponseHeaders().add("Content-Type", contentType);
        
        exchange.sendResponseHeaders(200, 0);
        exchange.getResponseBody().close();
    }
    
    private String extractParam(String query, String param) {
        // Simple extraction method for demo purposes
        return "parameter-value";
    }
}

public void bad_case_10() {
    // Using Spark framework to set headers with user input
    spark.Spark.get("/api", (Request req, Response res) -> {
        String authToken = req.queryParams("auth");
        
        // ruleid: java-crlf-injection
        res.header("Authorization", authToken);
        
        return "API response";
    });
}

public void bad_case_11() throws Exception {
    // Using Ratpack to set headers with user input
    RatpackServer.start(server -> server
        .handlers(chain -> chain
            .get("api", ctx -> {
                String language = ctx.getRequest().getQueryParams().get("lang");
                
                // ruleid: java-crlf-injection
                ctx.getResponse().getHeaders().add("Content-Language", language);
                
                ctx.render("API response");
            })
        )
    );
}

public class bad_case_12 extends AbstractHandler {
    // Using Jetty server to set headers with user input
    @Override
    public void handle(String target, Request baseRequest, 
                      javax.servlet.http.HttpServletRequest request,
                      javax.servlet.http.HttpServletResponse response) throws IOException {
        
        String encoding = request.getParameter("encoding");
        
        // ruleid: java-crlf-injection
        response.setHeader("Content-Encoding", encoding);
        
        response.setStatus(200);
        baseRequest.setHandled(true);
    }
}

public class bad_case_13 extends Controller {
    // Using Play Framework to set headers with user input
    public Result index(Http.Request request) {
        String cspHeader = request.getQueryString("csp");
        
        // ruleid: java-crlf-injection
        return ok("Result")
            .withHeader("Content-Security-Policy", cspHeader);
    }
}

public class bad_case_14 {
    // Using Jersey to set headers with user input
    public void addResponseHeaders(ContainerRequestContext requestContext, 
                                  ContainerResponseContext responseContext) {
        
        String headerValue = requestContext.getUriInfo().getQueryParameters().getFirst("header-value");
        
        // ruleid: java-crlf-injection
        responseContext.getHeaders().add("X-Custom-Header", headerValue);
    }
}

public class bad_case_15 extends ActionSupport implements ServletRequestAware, ServletResponseAware {
    // Using Apache Struts to set headers with user input
    private HttpServletRequest request;
    private HttpServletResponse response;
    
    public String execute() {
        String headerValue = request.getParameter("header-value");
        
        // ruleid: java-crlf-injection
        response.setHeader("X-Struts-Header", headerValue);
        
        return SUCCESS;
    }
    
    @Override
    public void setServletRequest(HttpServletRequest request) {
        this.request = request;
    }
    
    @Override
    public void setServletResponse(HttpServletResponse response) {
        this.response = response;
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Using raw Servlet API with sanitization
    String userInput = request.getParameter("location");
    
    // Sanitize the input to prevent CRLF injection
    String sanitizedInput = userInput.replaceAll("[\\r\\n]", "");
    
    // ok: java-crlf-injection
    response.setHeader("Location", sanitizedInput);
}

public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Using raw Servlet API with validation for cookie values
    String userValue = request.getParameter("value");
    
    // Validate and sanitize cookie value
    if (userValue != null && userValue.matches("[a-zA-Z0-9_-]+")) {
        Cookie cookie = new Cookie("sessionData", userValue);
        
        // ok: java-crlf-injection
        response.addCookie(cookie);
    } else {
        response.sendError(400, "Invalid cookie value");
    }
}

@RestController
public class good_case_3 {
    @GetMapping("/redirect")
    public ResponseEntity<String> redirectUser(HttpServletRequest request) {
        // Using Spring's ResponseEntity with validation
        String redirectUrl = request.getParameter("url");
        
        // Sanitize the URL to prevent CRLF injection
        String sanitizedUrl = redirectUrl.replaceAll("[\\r\\n]", "");
        
        HttpHeaders headers = new HttpHeaders();
        
        // ok: java-crlf-injection
        headers.add("Location", sanitizedUrl);
        
        return new ResponseEntity<>("Redirecting...", headers, 302);
    }
}

public void good_case_4() throws IOException {
    // Using Apache HttpClient with sanitization
    CloseableHttpClient httpClient = HttpClients.createDefault();
    String url = "https://example.com/api";
    HttpGet request = new HttpGet(url);
    
    // Simulating getting user input from an HTTP request
    String userAgent = getParameterFromRequest("user-agent");
    
    // Sanitize the input
    String sanitizedUserAgent = userAgent.replaceAll("[\\r\\n]", "");
    
    // ok: java-crlf-injection
    request.addHeader("User-Agent", sanitizedUserAgent);
    
    httpClient.execute(request);
}

public void good_case_5() throws IOException {
    // Using OkHttp with validation
    OkHttpClient client = new OkHttpClient();
    
    // Simulating getting user input from an HTTP request
    String referer = getParameterFromRequest("referer");
    
    // Sanitize the input
    String sanitizedReferer = referer.replaceAll("[\\r\\n]", "");
    
    Request request = new Request.Builder()
        .url("https://example.com/api")
        // ok: java-crlf-injection
        .header("Referer", sanitizedReferer)
        .build();
    
    client.newCall(request).execute();
}

public void good_case_6() throws IOException {
    // Using Java's HttpURLConnection with Apache Commons Text for sanitization
    URL url = new URL("https://example.com/api");
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    
    // Simulating getting user input from an HTTP request
    String contentType = getParameterFromRequest("content-type");
    
    // Use Apache Commons Text to escape special characters
    String sanitizedContentType = StringEscapeUtils.escapeJava(contentType)
                                   .replaceAll("[\\r\\n]", "");
    
    // ok: java-crlf-injection
    connection.setRequestProperty("Content-Type", sanitizedContentType);
    
    connection.connect();
}

public void good_case_7(Vertx vertx) {
    // Using Vert.x with OWASP Encoder
    Router router = Router.router(vertx);
    
    router.get("/api").handler(routingContext -> {
        HttpServerRequest request = routingContext.request();
        HttpServerResponse response = routingContext.response();
        
        String origin = request.getParam("origin");
        
        // Use OWASP Encoder to sanitize the input
        String sanitizedOrigin = Encode.forJava(origin).replaceAll("[\\r\\n]", "");
        
        // ok: java-crlf-injection
        response.putHeader("Access-Control-Allow-Origin", sanitizedOrigin);
        
        response.end("API response");
    });
}

public void good_case_8() {
    // Using Javalin with whitelist validation
    Javalin app = Javalin.create().start(7000);
    
    app.get("/api", ctx -> {
        String cacheControl = ctx.queryParam("cache");
        
        // Validate against a whitelist of allowed values
        String[] allowedValues = {"no-cache", "no-store", "must-revalidate"};
        String safeValue = "no-cache"; // Default value
        
        if (cacheControl != null) {
            for (String allowed : allowedValues) {
                if (allowed.equals(cacheControl)) {
                    safeValue = cacheControl;
                    break;
                }
            }
        }
        
        // ok: java-crlf-injection
        ctx.header("Cache-Control", safeValue);
        
        ctx.result("API response");
    });
}

public class good_case_9 implements HttpHandler {
    // Using com.sun.net.httpserver with StringUtils validation
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // Get query parameters
        String query = exchange.getRequestURI().getQuery();
        String contentType = extractParam(query, "type");
        
        // Validate content type using StringUtils
        String safeContentType = "text/plain"; // Default value
        String[] allowedTypes = {"text/plain", "application/json", "text/html"};
        
        if (StringUtils.isNotBlank(contentType)) {
            for (String type : allowedTypes) {
                if (type.equals(contentType)) {
                    safeContentType = contentType;
                    break;
                }
            }
        }
        
        // ok: java-crlf-injection
        exchange.getResponseHeaders().add("Content-Type", safeContentType);
        
        exchange.sendResponseHeaders(200, 0);
        exchange.getResponseBody().close();
    }
    
    private String extractParam(String query, String param) {
        // Simple extraction method for demo purposes
        return "parameter-value";
    }
}

public void good_case_10() {
    // Using Spark framework with proper validation
    spark.Spark.get("/api", (Request req, Response res) -> {
        String authToken = req.queryParams("auth");
        
        // Validate the token format (example: only alphanumeric characters)
        if (authToken != null && !authToken.matches("^[a-zA-Z0-9]+$")) {
            authToken = "invalid-token";
        }
        
        // ok: java-crlf-injection
        res.header("Authorization", authToken);
        
        return "API response";
    });
}

public void good_case_11() throws Exception {
    // Using Ratpack with sanitization
    RatpackServer.start(server -> server
        .handlers(chain -> chain
            .get("api", ctx -> {
                String language = ctx.getRequest().getQueryParams().get("lang");
                
                // Sanitize and validate language code (e.g., en-US, fr-FR)
                String sanitizedLanguage = "en-US"; // Default
                if (language != null && language.matches("^[a-z]{2}-[A-Z]{2}$")) {
                    sanitizedLanguage = language;
                }
                
                // ok: java-crlf-injection
                ctx.getResponse().getHeaders().add("Content-Language", sanitizedLanguage);
                
                ctx.render("API response");
            })
        )
    );
}

public class good_case_12 extends AbstractHandler {
    // Using Jetty server with validation
    @Override
    public void handle(String target, Request baseRequest, 
                      javax.servlet.http.HttpServletRequest request,
                      javax.servlet.http.HttpServletResponse response) throws IOException {
        
        String encoding = request.getParameter("encoding");
        
        // Validate encoding against allowed values
        String safeEncoding = "identity"; // Default
        String[] allowedEncodings = {"gzip", "deflate", "br", "identity"};
        
        if (encoding != null) {
            for (String allowed : allowedEncodings) {
                if (allowed.equals(encoding)) {
                    safeEncoding = encoding;
                    break;
                }
            }
        }
        
        // ok: java-crlf-injection
        response.setHeader("Content-Encoding", safeEncoding);
        
        response.setStatus(200);
        baseRequest.setHandled(true);
    }
}

public class good_case_13 extends Controller {
    // Using Play Framework with sanitization
    public Result index(Http.Request request) {
        String cspHeader = request.getQueryString("csp");
        
        // Sanitize CSP header value
        String sanitizedCsp = "default-src 'self'"; // Default safe value
        
        if (cspHeader != null) {
            // Remove any CR or LF characters
            sanitizedCsp = cspHeader.replaceAll("[\\r\\n]", "");
        }
        
        // ok: java-crlf-injection
        return ok("Result")
            .withHeader("Content-Security-Policy", sanitizedCsp);
    }
}

public class good_case_14 {
    // Using Jersey with sanitization
    public void addResponseHeaders(ContainerRequestContext requestContext, 
                                  ContainerResponseContext responseContext) {
        
        String headerValue = requestContext.getUriInfo().getQueryParameters().getFirst("header-value");
        
        // Sanitize the header value
        String sanitizedValue = null;
        if (headerValue != null) {
            sanitizedValue = headerValue.replaceAll("[\\r\\n]", "");
        } else {
            sanitizedValue = "default-value";
        }
        
        // ok: java-crlf-injection
        responseContext.getHeaders().add("X-Custom-Header", sanitizedValue);
    }
}

public class good_case_15 extends ActionSupport implements ServletRequestAware, ServletResponseAware {
    // Using Apache Struts with validation
    private HttpServletRequest request;
    private HttpServletResponse response;
    
    public String execute() {
        String headerValue = request.getParameter("header-value");
        
        // Sanitize and validate the header value
        String sanitizedValue = "default-value";
        if (headerValue != null && headerValue.matches("^[a-zA-Z0-9_\\-\\.]+$")) {
            sanitizedValue = headerValue;
        }
        
        // ok: java-crlf-injection
        response.setHeader("X-Struts-Header", sanitizedValue);
        
        return SUCCESS;
    }
    
    @Override
    public void setServletRequest(HttpServletRequest request) {
        this.request = request;
    }
    
    @Override
    public void setServletResponse(HttpServletResponse response) {
        this.response = response;
    }
}

// Helper method to simulate getting parameters from an HTTP request
private String getParameterFromRequest(String paramName) {
    // This is just a placeholder method to make the examples compile
    return "user-input-value";
}