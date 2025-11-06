import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PathVariable;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import org.apache.struts2.ServletActionContext;

import spark.Route;
import spark.Spark;

import ratpack.handling.Context;
import ratpack.handling.Handler;

import io.javalin.http.Context;
import io.javalin.Javalin;

import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;

import org.glassfish.jersey.server.ContainerRequest;

// Security Issue: Failing to compile Java regular expressions separately before using matching methods

// True Positive Examples (Vulnerable/Insecure Code)

public class PatternMatchesVulnerabilities {

    // Spring Framework example
    @RestController
    public static class BadCase1 {
        @GetMapping("/validate-email")
        public String validateEmail(@RequestParam String email) {
            // ruleid: java-proper-usage-of-pattern-matches
            if (Pattern.matches(email + "@example\\.com", "user@example.com")) {
                return "Valid email";
            }
            return "Invalid email";
        }
    }

    // Servlet API example
// {fact rule=permissive-regex@v1.0 defects=1}
    public static void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("pattern");
        String textToMatch = "sensitive-data-123";
        
        // ruleid: java-proper-usage-of-pattern-matches
        boolean isMatch = Pattern.matches(userInput, textToMatch);
        
        response.getWriter().println("Pattern match result: " + isMatch);
    }

    // OkHttp client example
    public static void bad_case_3() throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://example.com/api/pattern")
            .build();
            
        try (Response response = client.newCall(request).execute()) {
            String patternFromApi = response.body().string();
            String textToValidate = "user-input-123";
            
            // ruleid: java-proper-usage-of-pattern-matches
            boolean matches = Pattern.matches(patternFromApi, textToValidate);
            System.out.println("Validation result: " + matches);
        }
    }

    // Apache HttpClient example
    public static void bad_case_4() throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("https://example.com/api/regex");
            String patternFromServer = EntityUtils.toString(httpClient.execute(request).getEntity());
            
            String userContent = "test-content-123";
            
            // ruleid: java-proper-usage-of-pattern-matches
            if (Pattern.matches(patternFromServer, userContent)) {
                System.out.println("Content matches the pattern");
            }
        }
    }

    // Java built-in HttpServer example
    public static class BadCase5 implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            String pattern = query.split("=")[1];
            String dataToCheck = "confidential-data-456";
            
            // ruleid: java-proper-usage-of-pattern-matches
            boolean result = Pattern.matches(pattern, dataToCheck);
            
            String response = "Result: " + result;
            exchange.sendResponseHeaders(200, response.length());
            exchange.getResponseBody().write(response.getBytes());
            exchange.getResponseBody().close();
        }
    }

    // Apache Struts example
    public static class BadCase6 {
        public String execute() {
            String userPattern = ServletActionContext.getRequest().getParameter("pattern");
            String valueToCheck = "secure-token-789";
            
            // ruleid: java-proper-usage-of-pattern-matches
            if (Pattern.matches(userPattern, valueToCheck)) {
                return "success";
            }
            return "failure";
        }
    }

    // Spark Framework example
    public static void bad_case_7() {
        Spark.get("/validate", (req, res) -> {
            String pattern = req.queryParams("pattern");
            String input = "validate-this-string";
            
            // ruleid: java-proper-usage-of-pattern-matches
            boolean isValid = Pattern.matches(pattern, input);
            
            return "Validation result: " + isValid;
        });
    }

    // Ratpack example
    public static class BadCase8 implements Handler {
        @Override
        public void handle(Context ctx) {
            String pattern = ctx.getRequest().getQueryParams().get("regex");
            String dataToValidate = "important-data-123";
            
            // ruleid: java-proper-usage-of-pattern-matches
            boolean matches = Pattern.matches(pattern, dataToValidate);
            
            ctx.render("Match result: " + matches);
        }
    }

    // Javalin example
    public static void bad_case_9() {
        Javalin app = Javalin.create().start(7000);
        app.get("/check", ctx -> {
            String pattern = ctx.queryParam("pattern");
            String textToCheck = "verify-this-text";
            
            // ruleid: java-proper-usage-of-pattern-matches
            boolean result = Pattern.matches(pattern, textToCheck);
            
            ctx.result("Check result: " + result);
        });
    }

    // Vert.x example
    public static void bad_case_10() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/validate").handler(rc -> {
            String pattern = rc.request().getParam("pattern");
            String content = "content-to-validate";
            
            // ruleid: java-proper-usage-of-pattern-matches
            boolean valid = Pattern.matches(pattern, content);
            
            rc.response().end("Validation: " + valid);
        });
    }

    // Play Framework example
    public static class BadCase11 extends Controller {
        public Result validate(Http.Request request) {
            String pattern = request.getQueryString("pattern");
            String data = "data-to-validate";
            
            // ruleid: java-proper-usage-of-pattern-matches
            boolean isValid = Pattern.matches(pattern, data);
            
            return ok("Validation result: " + isValid);
        }
    }

    // Google HTTP Client example
    public static void bad_case_12() throws IOException {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        HttpRequest request = requestFactory.buildGetRequest(new GenericUrl("https://example.com/api/pattern"));
        
        String patternFromApi = request.execute().parseAsString();
        String dataToMatch = "match-this-data";
        
        // ruleid: java-proper-usage-of-pattern-matches
        boolean matches = Pattern.matches(patternFromApi, dataToMatch);
        
        System.out.println("Match result: " + matches);
    }

    // Jersey JAX-RS example
    public static class BadCase13 {
        public String validateData(ContainerRequest request) {
            String pattern = request.getUriInfo().getQueryParameters().getFirst("pattern");
            String dataToValidate = "validate-this-data";
            
            // ruleid: java-proper-usage-of-pattern-matches
            boolean isValid = Pattern.matches(pattern, dataToValidate);
            
            return "Validation result: " + isValid;
        }
    }

    // Direct String.matches() usage example (which internally uses Pattern.matches)
    public static void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userPattern = request.getParameter("pattern");
        String textToCheck = "text-to-check";
        
        // ruleid: java-proper-usage-of-pattern-matches
        boolean matches = textToCheck.matches(userPattern);
        
        response.getWriter().println("Match result: " + matches);
    }

    // Spring RequestBody example
    @RestController
    public static class BadCase15 {
        @PostMapping("/validate")
        public Map<String, Boolean> validatePattern(@RequestBody Map<String, String> payload) {
            String pattern = payload.get("pattern");
            String text = payload.get("text");
            
            Map<String, Boolean> result = new HashMap<>();
            // ruleid: java-proper-usage-of-pattern-matches
            result.put("isValid", Pattern.matches(pattern, text));
            
            return result;
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Spring Framework example - safe
    @RestController
    public static class GoodCase1 {
        @GetMapping("/validate-email-safe")
        public String validateEmailSafe(@RequestParam String email) {
            // Pre-compile the pattern
            // ok: java-proper-usage-of-pattern-matches
            Pattern emailPattern = Pattern.compile("user@example\\.com");
            Matcher matcher = emailPattern.matcher(email);
            
            if (matcher.matches()) {
                return "Valid email";
            }
            return "Invalid email";
        }
    }

    // Servlet API example - safe
    public static void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("pattern");
        String textToMatch = "sensitive-data-123";
        
        try {
            // ok: java-proper-usage-of-pattern-matches
            Pattern pattern = Pattern.compile(userInput);
            Matcher matcher = pattern.matcher(textToMatch);
            boolean isMatch = matcher.matches();
            
            response.getWriter().println("Pattern match result: " + isMatch);
        } catch (Exception e) {
            response.getWriter().println("Invalid pattern");
        }
    }

    // OkHttp client example - safe
    public static void good_case_3() throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://example.com/api/pattern")
            .build();
            
        try (Response response = client.newCall(request).execute()) {
            String patternFromApi = response.body().string();
            String textToValidate = "user-input-123";
            
            try {
                // ok: java-proper-usage-of-pattern-matches
                Pattern pattern = Pattern.compile(patternFromApi);
                Matcher matcher = pattern.matcher(textToValidate);
                boolean matches = matcher.matches();
                System.out.println("Validation result: " + matches);
            } catch (Exception e) {
                System.out.println("Invalid pattern received");
            }
        }
    }

    // Apache HttpClient example - safe
    public static void good_case_4() throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("https://example.com/api/regex");
            String patternFromServer = EntityUtils.toString(httpClient.execute(request).getEntity());
            
            String userContent = "test-content-123";
            
            try {
                // ok: java-proper-usage-of-pattern-matches
                Pattern pattern = Pattern.compile(patternFromServer);
                Matcher matcher = pattern.matcher(userContent);
                if (matcher.matches()) {
                    System.out.println("Content matches the pattern");
                }
            } catch (Exception e) {
                System.out.println("Invalid pattern received from server");
            }
        }
    }

    // Java built-in HttpServer example - safe
    public static class GoodCase5 implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            String patternStr = query.split("=")[1];
            String dataToCheck = "confidential-data-456";
            
            String response;
            try {
                // ok: java-proper-usage-of-pattern-matches
                Pattern pattern = Pattern.compile(patternStr);
                Matcher matcher = pattern.matcher(dataToCheck);
                boolean result = matcher.matches();
                
                response = "Result: " + result;
            } catch (Exception e) {
                response = "Invalid pattern";
            }
            
            exchange.sendResponseHeaders(200, response.length());
            exchange.getResponseBody().write(response.getBytes());
            exchange.getResponseBody().close();
        }
    }

    // Apache Struts example - safe
    public static class GoodCase6 {
        public String execute() {
            String userPattern = ServletActionContext.getRequest().getParameter("pattern");
            String valueToCheck = "secure-token-789";
            
            try {
                // ok: java-proper-usage-of-pattern-matches
                Pattern pattern = Pattern.compile(userPattern);
                Matcher matcher = pattern.matcher(valueToCheck);
                if (matcher.matches()) {
                    return "success";
                }
            } catch (Exception e) {
                // Handle invalid pattern
            }
            return "failure";
        }
    }

    // Spark Framework example - safe
    public static void good_case_7() {
        Spark.get("/validate", (req, res) -> {
            String patternStr = req.queryParams("pattern");
            String input = "validate-this-string";
            
            try {
                // ok: java-proper-usage-of-pattern-matches
                Pattern pattern = Pattern.compile(patternStr);
                Matcher matcher = pattern.matcher(input);
                boolean isValid = matcher.matches();
                
                return "Validation result: " + isValid;
            } catch (Exception e) {
                return "Invalid pattern provided";
            }
        });
    }

    // Ratpack example - safe
    public static class GoodCase8 implements Handler {
        @Override
        public void handle(Context ctx) {
            String patternStr = ctx.getRequest().getQueryParams().get("regex");
            String dataToValidate = "important-data-123";
            
            try {
                // ok: java-proper-usage-of-pattern-matches
                Pattern pattern = Pattern.compile(patternStr);
                Matcher matcher = pattern.matcher(dataToValidate);
                boolean matches = matcher.matches();
                
                ctx.render("Match result: " + matches);
            } catch (Exception e) {
                ctx.render("Invalid pattern provided");
            }
        }
    }

    // Javalin example - safe
    public static void good_case_9() {
        Javalin app = Javalin.create().start(7000);
        app.get("/check", ctx -> {
            String patternStr = ctx.queryParam("pattern");
            String textToCheck = "verify-this-text";
            
            try {
                // ok: java-proper-usage-of-pattern-matches
                Pattern pattern = Pattern.compile(patternStr);
                Matcher matcher = pattern.matcher(textToCheck);
                boolean result = matcher.matches();
                
                ctx.result("Check result: " + result);
            } catch (Exception e) {
                ctx.result("Invalid pattern");
            }
        });
    }

    // Vert.x example - safe
    public static void good_case_10() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/validate").handler(rc -> {
            String patternStr = rc.request().getParam("pattern");
            String content = "content-to-validate";
            
            try {
                // ok: java-proper-usage-of-pattern-matches
                Pattern pattern = Pattern.compile(patternStr);
                Matcher matcher = pattern.matcher(content);
                boolean valid = matcher.matches();
                
                rc.response().end("Validation: " + valid);
            } catch (Exception e) {
                rc.response().end("Invalid pattern provided");
            }
        });
    }

    // Play Framework example - safe
    public static class GoodCase11 extends Controller {
        public Result validate(Http.Request request) {
            String patternStr = request.getQueryString("pattern");
            String data = "data-to-validate";
            
            try {
                // ok: java-proper-usage-of-pattern-matches
                Pattern pattern = Pattern.compile(patternStr);
                Matcher matcher = pattern.matcher(data);
                boolean isValid = matcher.matches();
                
                return ok("Validation result: " + isValid);
            } catch (Exception e) {
                return badRequest("Invalid pattern");
            }
        }
    }

    // Google HTTP Client example - safe
    public static void good_case_12() throws IOException {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        HttpRequest request = requestFactory.buildGetRequest(new GenericUrl("https://example.com/api/pattern"));
        
        String patternFromApi = request.execute().parseAsString();
        String dataToMatch = "match-this-data";
        
        try {
            // ok: java-proper-usage-of-pattern-matches
            Pattern pattern = Pattern.compile(patternFromApi);
            Matcher matcher = pattern.matcher(dataToMatch);
            boolean matches = matcher.matches();
            
            System.out.println("Match result: " + matches);
        } catch (Exception e) {
            System.out.println("Invalid pattern received from API");
        }
    }

    // Jersey JAX-RS example - safe
    public static class GoodCase13 {
        public String validateData(ContainerRequest request) {
            String patternStr = request.getUriInfo().getQueryParameters().getFirst("pattern");
            String dataToValidate = "validate-this-data";
            
            try {
                // ok: java-proper-usage-of-pattern-matches
                Pattern pattern = Pattern.compile(patternStr);
                Matcher matcher = pattern.matcher(dataToValidate);
                boolean isValid = matcher.matches();
                
                return "Validation result: " + isValid;
            } catch (Exception e) {
                return "Invalid pattern provided";
            }
        }
    }

    // Safe alternative to String.matches()
    public static void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userPattern = request.getParameter("pattern");
        String textToCheck = "text-to-check";
        
        try {
            // ok: java-proper-usage-of-pattern-matches
            Pattern pattern = Pattern.compile(userPattern);
            Matcher matcher = pattern.matcher(textToCheck);
            boolean matches = matcher.matches();
            
            response.getWriter().println("Match result: " + matches);
        } catch (Exception e) {
            response.getWriter().println("Invalid pattern");
        }
    }

    // Spring RequestBody example - safe
    @RestController
    public static class GoodCase15 {
        @PostMapping("/validate")
        public Map<String, Object> validatePattern(@RequestBody Map<String, String> payload) {
            String patternStr = payload.get("pattern");
            String text = payload.get("text");
            
            Map<String, Object> result = new HashMap<>();
            try {
                // ok: java-proper-usage-of-pattern-matches
                Pattern pattern = Pattern.compile(patternStr);
                Matcher matcher = pattern.matcher(text);
                result.put("isValid", matcher.matches());
                result.put("status", "success");
            } catch (Exception e) {
                result.put("status", "error");
                result.put("message", "Invalid pattern");
            }
            
            return result;
        }
    }
}
// {/fact}