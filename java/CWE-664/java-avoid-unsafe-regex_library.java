import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import spark.Spark;
import io.javalin.Javalin;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import ratpack.server.RatpackServer;
import ratpack.handling.Context;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import org.apache.commons.validator.routines.RegexValidator;
import org.apache.commons.lang3.StringUtils;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.glassfish.jersey.server.ContainerRequest;
import javax.ws.rs.core.Response;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Retrofit;
import retrofit2.http.GET;
import retrofit2.http.Query;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

// Security Issue: Constructing regular expressions from user-controlled input can lead to ReDoS (Regular Expression Denial of Service) attacks

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    String userInput = request.getParameter("pattern");
    
    // ruleid: java-avoid-unsafe-regex
    Pattern pattern = Pattern.compile(userInput);
    Matcher matcher = pattern.matcher("test string");
    
    if (matcher.matches()) {
        System.out.println("Match found!");
    }
}

@RestController
public class bad_case_2 {
    @GetMapping("/search")
    public String searchWithRegex(@RequestParam String regex) {
        // ruleid: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher("content to search");
        
        return matcher.find() ? "Found match" : "No match";
    }
}

public class bad_case_3 implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String query = exchange.getRequestURI().getQuery();
        String regexParam = query.split("=")[1];
        
        // ruleid: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(regexParam);
        Matcher matcher = pattern.matcher("text to validate");
        
        String response = matcher.matches() ? "Valid" : "Invalid";
        exchange.sendResponseHeaders(200, response.length());
        exchange.getResponseBody().write(response.getBytes());
        exchange.close();
    }
}

public class bad_case_4 {
    public void processOkHttpRequest() throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://example.com/api/regex")
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            String regexFromApi = response.body().string();
            
            // ruleid: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(regexFromApi);
            Matcher matcher = pattern.matcher("test data");
            
            if (matcher.find()) {
                System.out.println("Pattern found in data");
            }
        }
    }
}

public class bad_case_5 {
    public void sparkExample() {
        Spark.get("/validate", (req, res) -> {
            String userRegex = req.queryParams("regex");
            String textToMatch = "validate this text";
            
            // ruleid: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(userRegex);
            Matcher matcher = pattern.matcher(textToMatch);
            
            return matcher.matches() ? "Valid input" : "Invalid input";
        });
    }
}

public class bad_case_6 {
    public void javalinExample() {
        Javalin app = Javalin.create().start(7000);
        app.get("/regex", ctx -> {
            String regexPattern = ctx.queryParam("pattern");
            
            // ruleid: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(regexPattern);
            Matcher matcher = pattern.matcher("test string");
            
            ctx.result(matcher.matches() ? "Match found" : "No match");
        });
    }
}

public class bad_case_7 {
    public void vertxExample() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/validate").handler(rc -> {
            String userPattern = rc.request().getParam("pattern");
            
            // ruleid: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(userPattern);
            Matcher matcher = pattern.matcher("text to validate");
            
            rc.response().end(matcher.matches() ? "Valid" : "Invalid");
        });
    }
}

public class bad_case_8 {
    public void ratpackExample() throws Exception {
        RatpackServer.start(server -> server
            .handlers(chain -> chain
                .get("regex", ctx -> {
                    String patternInput = ctx.getRequest().getQueryParams().get("pattern");
                    
                    // ruleid: java-avoid-unsafe-regex
                    Pattern pattern = Pattern.compile(patternInput);
                    Matcher matcher = pattern.matcher("test content");
                    
                    ctx.render(matcher.matches() ? "Valid pattern" : "Invalid pattern");
                })
            )
        );
    }
}

public class bad_case_9 {
    public void googleHttpClientExample() throws IOException {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        GenericUrl url = new GenericUrl("https://example.com/api/pattern");
        
        com.google.api.client.http.HttpRequest request = requestFactory.buildGetRequest(url);
        com.google.api.client.http.HttpResponse response = request.execute();
        
        String patternFromApi = response.parseAsString();
        
        // ruleid: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(patternFromApi);
        Matcher matcher = pattern.matcher("content to match");
        
        System.out.println(matcher.matches() ? "Valid" : "Invalid");
    }
}

public class bad_case_10 implements RequestHandler<APIGatewayProxyRequestEvent, String> {
    @Override
    public String handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        Map<String, String> queryParams = input.getQueryStringParameters();
        String regexPattern = queryParams.get("pattern");
        
        // ruleid: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(regexPattern);
        Matcher matcher = pattern.matcher("test string");
        
        return matcher.matches() ? "Valid pattern" : "Invalid pattern";
    }
}

@Path("/api")
public class bad_case_11 {
    @GET
    @Path("/validate")
    public Response validateWithRegex(@QueryParam("pattern") String pattern) {
        String textToValidate = "validate this text";
        
        // ruleid: java-avoid-unsafe-regex
        Pattern regexPattern = Pattern.compile(pattern);
        Matcher matcher = regexPattern.matcher(textToValidate);
        
        return Response.ok(matcher.matches() ? "Valid" : "Invalid").build();
    }
}

public class bad_case_12 {
    interface RegexApi {
        @GET("pattern")
        Call<String> getPattern(@Query("type") String type);
    }
    
    public void retrofitExample() {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
        
        RegexApi api = retrofit.create(RegexApi.class);
        
        try {
            String patternFromApi = api.getPattern("email").execute().body();
            
            // ruleid: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(patternFromApi);
            Matcher matcher = pattern.matcher("test@example.com");
            
            System.out.println(matcher.matches() ? "Valid email" : "Invalid email");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public class bad_case_13 extends AbstractHandler {
    @Override
    public void handle(String target, Request baseRequest, 
                      org.eclipse.jetty.server.HttpServletRequest request,
                      org.eclipse.jetty.server.HttpServletResponse response) throws IOException {
        String regexInput = request.getParameter("regex");
        
        // ruleid: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(regexInput);
        Matcher matcher = pattern.matcher("text to match");
        
        response.setContentType("text/plain");
        response.getWriter().println(matcher.matches() ? "Match found" : "No match");
        baseRequest.setHandled(true);
    }
}

public class bad_case_14 extends Controller {
    public Result validateRegex(Http.Request request) {
        String pattern = request.queryString().get("pattern")[0];
        String textToMatch = "validate this text";
        
        // ruleid: java-avoid-unsafe-regex
        Pattern regexPattern = Pattern.compile(pattern);
        Matcher matcher = regexPattern.matcher(textToMatch);
        
        return ok(matcher.matches() ? "Valid" : "Invalid");
    }
}

public class bad_case_15 {
    public void javaHttpClientExample() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api/regex"))
            .build();
        
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        String patternFromApi = response.body();
        
        // ruleid: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(patternFromApi);
        Matcher matcher = pattern.matcher("text to validate");
        
        System.out.println(matcher.matches() ? "Valid pattern" : "Invalid pattern");
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    String userInput = request.getParameter("pattern");
    
    // Validate that the input is a safe regex pattern
    if (userInput != null && userInput.matches("^[a-zA-Z0-9]+$")) {
        // ok: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(userInput);
        Matcher matcher = pattern.matcher("test string");
        
        if (matcher.matches()) {
            System.out.println("Match found!");
        }
    } else {
        System.out.println("Invalid regex pattern");
    }
}

@RestController
public class good_case_2 {
    private static final Map<String, String> SAFE_PATTERNS = new HashMap<>();
    
    static {
        SAFE_PATTERNS.put("email", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");
        SAFE_PATTERNS.put("phone", "^\\d{10}$");
        SAFE_PATTERNS.put("zipcode", "^\\d{5}(-\\d{4})?$");
    }
    
    @GetMapping("/search")
    public String searchWithRegex(@RequestParam String type) {
        String safeRegex = SAFE_PATTERNS.getOrDefault(type, ".*");
        
        // ok: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(safeRegex);
        Matcher matcher = pattern.matcher("content to search");
        
        return matcher.find() ? "Found match" : "No match";
    }
}

public class good_case_3 implements HttpHandler {
    private static final int MAX_REGEX_LENGTH = 50;
    
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String query = exchange.getRequestURI().getQuery();
        String regexParam = query.split("=")[1];
        
        // Limit regex length to prevent complex patterns
        if (regexParam.length() > MAX_REGEX_LENGTH) {
            regexParam = regexParam.substring(0, MAX_REGEX_LENGTH);
        }
        
        try {
            // ok: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(regexParam, Pattern.LITERAL); // Use LITERAL flag to treat as literal string
            Matcher matcher = pattern.matcher("text to validate");
            
            String response = matcher.find() ? "Found" : "Not found";
            exchange.sendResponseHeaders(200, response.length());
            exchange.getResponseBody().write(response.getBytes());
        } catch (Exception e) {
            String error = "Invalid regex";
            exchange.sendResponseHeaders(400, error.length());
            exchange.getResponseBody().write(error.getBytes());
        } finally {
            exchange.close();
        }
    }
}

public class good_case_4 {
    private static final List<String> ALLOWED_PATTERNS = new ArrayList<>();
    
    static {
        ALLOWED_PATTERNS.add("\\d+"); // digits
        ALLOWED_PATTERNS.add("[a-zA-Z]+"); // letters
        ALLOWED_PATTERNS.add("[a-zA-Z0-9]+"); // alphanumeric
    }
    
    public void processOkHttpRequest() throws IOException {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://example.com/api/regex")
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            String regexFromApi = response.body().string();
            
            // Only use the pattern if it's in our allowed list
            if (ALLOWED_PATTERNS.contains(regexFromApi)) {
                // ok: java-avoid-unsafe-regex
                Pattern pattern = Pattern.compile(regexFromApi);
                Matcher matcher = pattern.matcher("test data");
                
                if (matcher.find()) {
                    System.out.println("Pattern found in data");
                }
            } else {
                System.out.println("Pattern not allowed");
            }
        }
    }
}

public class good_case_5 {
    public void sparkExample() {
        Spark.get("/validate", (req, res) -> {
            String userRegex = req.queryParams("regex");
            String textToMatch = "validate this text";
            
            // Use regex validator to check if pattern is safe
            RegexValidator validator = new RegexValidator(userRegex);
            if (validator.isValid(textToMatch)) {
                // ok: java-avoid-unsafe-regex
                Pattern pattern = Pattern.compile(StringUtils.substring(userRegex, 0, 100)); // Limit length
                Matcher matcher = pattern.matcher(textToMatch);
                
                return matcher.matches() ? "Valid input" : "Invalid input";
            } else {
                return "Invalid regex pattern";
            }
        });
    }
}

public class good_case_6 {
    private static final Pattern SAFE_PATTERN = Pattern.compile("[a-zA-Z0-9]+");
    
    public void javalinExample() {
        Javalin app = Javalin.create().start(7000);
        app.get("/regex", ctx -> {
            String regexPattern = ctx.queryParam("pattern");
            
            // First validate that the input pattern itself matches our safe pattern
            if (regexPattern != null && SAFE_PATTERN.matcher(regexPattern).matches()) {
                // ok: java-avoid-unsafe-regex
                Pattern pattern = Pattern.compile(regexPattern);
                Matcher matcher = pattern.matcher("test string");
                
                ctx.result(matcher.matches() ? "Match found" : "No match");
            } else {
                ctx.result("Invalid regex pattern");
            }
        });
    }
}

public class good_case_7 {
    private static final Map<String, Pattern> PRE_COMPILED_PATTERNS = new HashMap<>();
    
    static {
        PRE_COMPILED_PATTERNS.put("email", Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$"));
        PRE_COMPILED_PATTERNS.put("phone", Pattern.compile("^\\d{10}$"));
        PRE_COMPILED_PATTERNS.put("zipcode", Pattern.compile("^\\d{5}(-\\d{4})?$"));
    }
    
    public void vertxExample() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/validate").handler(rc -> {
            String patternType = rc.request().getParam("type");
            String textToValidate = rc.request().getParam("text");
            
            // Use pre-compiled patterns instead of user input
            // ok: java-avoid-unsafe-regex
            Pattern pattern = PRE_COMPILED_PATTERNS.getOrDefault(patternType, Pattern.compile(".*"));
            Matcher matcher = pattern.matcher(textToValidate != null ? textToValidate : "");
            
            rc.response().end(matcher.matches() ? "Valid" : "Invalid");
        });
    }
}

public class good_case_8 {
    public void ratpackExample() throws Exception {
        RatpackServer.start(server -> server
            .handlers(chain -> chain
                .get("regex", ctx -> {
                    String patternType = ctx.getRequest().getQueryParams().get("type");
                    
                    // Use a switch statement to select from predefined patterns
                    String safePattern;
                    switch (patternType) {
                        case "email":
                            safePattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$";
                            break;
                        case "phone":
                            safePattern = "^\\d{10}$";
                            break;
                        default:
                            safePattern = "^[a-zA-Z0-9]+$";
                    }
                    
                    // ok: java-avoid-unsafe-regex
                    Pattern pattern = Pattern.compile(safePattern);
                    Matcher matcher = pattern.matcher("test content");
                    
                    ctx.render(matcher.matches() ? "Valid pattern" : "Invalid pattern");
                })
            )
        );
    }
}

public class good_case_9 {
    private static final Pattern SAFE_INPUT_PATTERN = Pattern.compile("^[a-zA-Z0-9]+$");
    
    public void googleHttpClientExample() throws IOException {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        GenericUrl url = new GenericUrl("https://example.com/api/pattern");
        
        com.google.api.client.http.HttpRequest request = requestFactory.buildGetRequest(url);
        com.google.api.client.http.HttpResponse response = request.execute();
        
        String patternFromApi = response.parseAsString();
        
        // Validate the pattern before using it
        if (SAFE_INPUT_PATTERN.matcher(patternFromApi).matches()) {
            // ok: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(patternFromApi);
            Matcher matcher = pattern.matcher("content to match");
            
            System.out.println(matcher.matches() ? "Valid" : "Invalid");
        } else {
            System.out.println("Unsafe pattern received");
        }
    }
}

public class good_case_10 implements RequestHandler<APIGatewayProxyRequestEvent, String> {
    private static final Pattern[] SAFE_PATTERNS = {
        Pattern.compile("\\d+"),
        Pattern.compile("[a-zA-Z]+"),
        Pattern.compile("[a-zA-Z0-9]+")
    };
    
    @Override
    public String handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        Map<String, String> queryParams = input.getQueryStringParameters();
        String patternIndex = queryParams.get("patternIndex");
        
        try {
            int index = Integer.parseInt(patternIndex);
            if (index >= 0 && index < SAFE_PATTERNS.length) {
                // ok: java-avoid-unsafe-regex
                Pattern pattern = SAFE_PATTERNS[index];
                Matcher matcher = pattern.matcher("test string");
                
                return matcher.matches() ? "Valid pattern" : "Invalid pattern";
            } else {
                return "Invalid pattern index";
            }
        } catch (NumberFormatException e) {
            return "Invalid input";
        }
    }
}

@Path("/api")
public class good_case_11 {
    private static final int PATTERN_TIMEOUT_MS = 1000; // 1 second timeout
    
    @GET
    @Path("/validate")
    public Response validateWithRegex(@QueryParam("pattern") String pattern) {
        String textToValidate = "validate this text";
        
        try {
            // ok: java-avoid-unsafe-regex
            Pattern regexPattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE | Pattern.LITERAL); // Use LITERAL flag to treat as literal string
            Matcher matcher = regexPattern.matcher(textToValidate);
            
            // Set a timeout for the matching operation
            boolean matched = false;
            Thread matchThread = new Thread(() -> {
                matcher.matches();
            });
            matchThread.start();
            matchThread.join(PATTERN_TIMEOUT_MS);
            
            if (matchThread.isAlive()) {
                matchThread.interrupt();
                return Response.status(Response.Status.REQUEST_TIMEOUT)
                    .entity("Regex evaluation timed out")
                    .build();
            }
            
            return Response.ok(matcher.matches() ? "Valid" : "Invalid").build();
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity("Invalid regex pattern")
                .build();
        }
    }
}

public class good_case_12 {
    interface RegexApi {
        @GET("pattern")
        Call<String> getPattern(@Query("type") String type);
    }
    
    private static final Map<String, String> SAFE_PATTERNS = new HashMap<>();
    
    static {
        SAFE_PATTERNS.put("email", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");
        SAFE_PATTERNS.put("phone", "^\\d{10}$");
        SAFE_PATTERNS.put("zipcode", "^\\d{5}(-\\d{4})?$");
    }
    
    public void retrofitExample() {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
        
        RegexApi api = retrofit.create(RegexApi.class);
        
        try {
            String patternType = api.getPattern("email").execute().body();
            
            // Use a predefined pattern based on the type
            String safePattern = SAFE_PATTERNS.getOrDefault(patternType, ".*");
            
            // ok: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(safePattern);
            Matcher matcher = pattern.matcher("test@example.com");
            
            System.out.println(matcher.matches() ? "Valid email" : "Invalid email");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public class good_case_13 extends AbstractHandler {
    private static final List<Pattern> ALLOWED_PATTERNS = new ArrayList<>();
    
    static {
        ALLOWED_PATTERNS.add(Pattern.compile("\\d+"));
        ALLOWED_PATTERNS.add(Pattern.compile("[a-zA-Z]+"));
        ALLOWED_PATTERNS.add(Pattern.compile("[a-zA-Z0-9]+"));
    }
    
    @Override
    public void handle(String target, Request baseRequest, 
                      org.eclipse.jetty.server.HttpServletRequest request,
                      org.eclipse.jetty.server.HttpServletResponse response) throws IOException {
        String patternIndex = request.getParameter("patternIndex");
        
        try {
            int index = Integer.parseInt(patternIndex);
            if (index >= 0 && index < ALLOWED_PATTERNS.size()) {
                // ok: java-avoid-unsafe-regex
                Pattern pattern = ALLOWED_PATTERNS.get(index);
                Matcher matcher = pattern.matcher("text to match");
                
                response.setContentType("text/plain");
                response.getWriter().println(matcher.matches() ? "Match found" : "No match");
            } else {
                response.setContentType("text/plain");
                response.getWriter().println("Invalid pattern index");
            }
        } catch (NumberFormatException e) {
            response.setContentType("text/plain");
            response.getWriter().println("Invalid input");
        }
        
        baseRequest.setHandled(true);
    }
}

public class good_case_14 extends Controller {
    private static final Map<String, Pattern> PATTERN_MAP = new HashMap<>();
    
    static {
        PATTERN_MAP.put("email", Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$"));
        PATTERN_MAP.put("phone", Pattern.compile("^\\d{10}$"));
        PATTERN_MAP.put("zipcode", Pattern.compile("^\\d{5}(-\\d{4})?$"));
    }
    
    public Result validateRegex(Http.Request request) {
        String patternType = request.queryString().get("type")[0];
        String textToMatch = "validate this text";
        
        // Use a predefined pattern from our map
        // ok: java-avoid-unsafe-regex
        Pattern regexPattern = PATTERN_MAP.getOrDefault(patternType, Pattern.compile(".*"));
        Matcher matcher = regexPattern.matcher(textToMatch);
        
        return ok(matcher.matches() ? "Valid" : "Invalid");
    }
}

public class good_case_15 {
    private static final Pattern SAFE_INPUT_VALIDATOR = Pattern.compile("^[a-zA-Z0-9]+$");
    
    public void javaHttpClientExample() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api/regex"))
            .build();
        
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        String patternFromApi = response.body();
        
        // Validate the pattern is safe before using it
        if (patternFromApi != null && SAFE_INPUT_VALIDATOR.matcher(patternFromApi).matches()) {
            // ok: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(patternFromApi);
            Matcher matcher = pattern.matcher("text to validate");
            
            System.out.println(matcher.matches() ? "Valid pattern" : "Invalid pattern");
        } else {
            System.out.println("Unsafe pattern received");
        }
    }
}