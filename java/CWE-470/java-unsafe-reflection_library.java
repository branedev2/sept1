import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.Gson;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import spark.Route;
import spark.Spark;

import io.javalin.Javalin;
import io.javalin.http.Context;

import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

import org.glassfish.jersey.server.ResourceConfig;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;

import ratpack.server.RatpackServer;
import ratpack.handling.Handler;
import ratpack.handling.Context;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;

import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.client.RestTemplate;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Retrofit;
import retrofit2.http.GET;
import retrofit2.http.Query;

// Security Issue: Unsafe reflection using Class.forName() with untrusted input from HTTP requests

// True Positive Examples (Vulnerable/Insecure Code)

@RestController
public class UnsafeReflectionExamples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
    // Example 1: Spring MVC Framework with RequestParam
// {fact rule=unsafe-reflection@v1.0 defects=1}
    @GetMapping("/bad1")
    public void bad_case_1(@RequestParam String className) {
        try {
            // ruleid: java-unsafe-reflection
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.newInstance();
            System.out.println("Created instance: " + instance);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 2: Spring MVC Framework with JSON body
    @PostMapping("/bad2")
    public void bad_case_2(@RequestBody Map<String, String> payload) {
        String className = payload.get("className");
        try {
            // ruleid: java-unsafe-reflection
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.newInstance();
            System.out.println("Created instance: " + instance);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 3: Servlet API
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
        String className = request.getParameter("class");
        try {
            // ruleid: java-unsafe-reflection
            Class<?> clazz = Class.forName(className);
            Method method = clazz.getMethod("execute");
            method.invoke(clazz.newInstance());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 4: OkHttp Client
    public void bad_case_4() {
        try {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                .url("https://example.com/api/class")
                .build();
            Response response = client.newCall(request).execute();
            String className = response.body().string();
            
            // ruleid: java-unsafe-reflection
            Class<?> clazz = Class.forName(className);
            Constructor<?> constructor = clazz.getConstructor();
            Object instance = constructor.newInstance();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 5: Apache HttpClient
    public void bad_case_5() {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("https://example.com/api/class");
            org.apache.http.HttpResponse response = httpClient.execute(request);
            String className = EntityUtils.toString(response.getEntity());
            
            // ruleid: java-unsafe-reflection
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.newInstance();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 6: Spark Framework
    public void bad_case_6() {
        Spark.get("/api/load", (req, res) -> {
            String className = req.queryParams("class");
            try {
                // ruleid: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                return clazz.getName();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        });
    }
    
    // Example 7: Javalin Framework
    public void bad_case_7() {
        Javalin app = Javalin.create().start(7000);
        app.get("/load-class", ctx -> {
            String className = ctx.queryParam("name");
            try {
                // ruleid: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                ctx.result("Loaded class: " + clazz.getName());
            } catch (Exception e) {
                ctx.result("Error: " + e.getMessage());
            }
        });
    }
    
    // Example 8: Vert.x Framework
    public void bad_case_8() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.get("/api/class").handler(routingContext -> {
            String className = routingContext.request().getParam("name");
            try {
                // ruleid: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                routingContext.response().end("Loaded: " + clazz.getName());
            } catch (Exception e) {
                routingContext.response().end("Error: " + e.getMessage());
            }
        });
    }
    
    // Example 9: Jersey Framework
    @Path("/api")
    public static class JerseyResource {
        @GET
        @Path("/load")
        public String bad_case_9(@QueryParam("className") String className) {
            try {
                // ruleid: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                return "Loaded: " + clazz.getName();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
    
    // Example 10: Ratpack Framework
    public void bad_case_10() throws Exception {
        RatpackServer.start(server -> server
            .handlers(chain -> chain
                .get("load", ctx -> {
                    String className = ctx.getRequest().getQueryParams().get("name");
                    try {
                        // ruleid: java-unsafe-reflection
                        Class<?> clazz = Class.forName(className);
                        ctx.render("Loaded: " + clazz.getName());
                    } catch (Exception e) {
                        ctx.render("Error: " + e.getMessage());
                    }
                })
            )
        );
    }
    
    // Example 11: Jetty Server
    public void bad_case_11() throws Exception {
        Server server = new Server(8080);
        server.setHandler(new AbstractHandler() {
            @Override
            public void handle(String target, Request baseRequest, 
                              javax.servlet.http.HttpServletRequest request, 
                              javax.servlet.http.HttpServletResponse response) throws IOException {
                String className = request.getParameter("class");
                try {
                    // ruleid: java-unsafe-reflection
                    Class<?> clazz = Class.forName(className);
                    response.getWriter().println("Loaded: " + clazz.getName());
                } catch (Exception e) {
                    response.getWriter().println("Error: " + e.getMessage());
                }
                baseRequest.setHandled(true);
            }
        });
        server.start();
    }
    
    // Example 12: AWS Lambda Function
    public class LambdaHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
        @Override
        public APIGatewayProxyResponseEvent bad_case_12(APIGatewayProxyRequestEvent input, Context context) {
            Map<String, String> queryParams = input.getQueryStringParameters();
            String className = queryParams.get("class");
            
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            try {
                // ruleid: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                response.setBody("Loaded: " + clazz.getName());
                response.setStatusCode(200);
            } catch (Exception e) {
                response.setBody("Error: " + e.getMessage());
                response.setStatusCode(500);
            }
            return response;
        }
    }
    
    // Example 13: Google Cloud Function
    public class CloudFunction implements HttpFunction {
        @Override
        public void bad_case_13(HttpRequest request, HttpResponse response) throws Exception {
            String className = request.getFirstQueryParameter("class").orElse("");
            try {
                // ruleid: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                response.getWriter().write("Loaded: " + clazz.getName());
            } catch (Exception e) {
                response.getWriter().write("Error: " + e.getMessage());
            }
        }
    }
    
    // Example 14: Spring RestTemplate
    public void bad_case_14() {
        RestTemplate restTemplate = new RestTemplateBuilder().build();
        String className = restTemplate.getForObject("https://example.com/api/class", String.class);
        try {
            // ruleid: java-unsafe-reflection
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.newInstance();
            System.out.println("Created: " + instance);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 15: Retrofit API Client
    public interface ApiService {
        @GET("/api/class")
        Call<String> getClassName();
    }
    
    public void bad_case_15() {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://example.com")
            .build();
        
        ApiService service = retrofit.create(ApiService.class);
        try {
            String className = service.getClassName().execute().body();
            // ruleid: java-unsafe-reflection
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.newInstance();
            System.out.println("Created: " + instance);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Example 1: Spring MVC with whitelist validation
    @GetMapping("/good1")
    public void good_case_1(@RequestParam String className) {
        try {
            // Define a whitelist of allowed classes
            List<String> allowedClasses = new ArrayList<>();
            allowedClasses.add("java.util.ArrayList");
            allowedClasses.add("java.util.HashMap");
            
            if (allowedClasses.contains(className)) {
                // ok: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                Object instance = clazz.newInstance();
                System.out.println("Created instance: " + instance);
            } else {
                System.out.println("Class not allowed: " + className);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 2: Spring MVC with pattern validation
    @PostMapping("/good2")
    public void good_case_2(@RequestBody Map<String, String> payload) {
        String className = payload.get("className");
        try {
            // Validate class name with regex pattern
            Pattern pattern = Pattern.compile("^java\\.util\\.[A-Za-z]+$");
            if (pattern.matcher(className).matches()) {
                // ok: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                Object instance = clazz.newInstance();
                System.out.println("Created instance: " + instance);
            } else {
                System.out.println("Invalid class name pattern: " + className);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 3: Servlet API with enum mapping
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
        String classKey = request.getParameter("classKey");
        try {
            // Use a map to safely map input to class names
            Map<String, String> classMap = new HashMap<>();
            classMap.put("list", "java.util.ArrayList");
            classMap.put("map", "java.util.HashMap");
            
            String className = classMap.get(classKey);
            if (className != null) {
                // ok: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                Object instance = clazz.newInstance();
                response.getWriter().write("Created: " + instance);
            } else {
                response.getWriter().write("Invalid class key");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 4: OkHttp Client with package prefix validation
    public void good_case_4() {
        try {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                .url("https://example.com/api/class")
                .build();
            Response response = client.newCall(request).execute();
            String className = response.body().string();
            
            // Validate class is from a safe package
            if (className != null && className.startsWith("com.myapp.safe.")) {
                // ok: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                Constructor<?> constructor = clazz.getConstructor();
                Object instance = constructor.newInstance();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 5: Apache HttpClient with class type checking
    public void good_case_5() {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("https://example.com/api/class");
            org.apache.http.HttpResponse response = httpClient.execute(request);
            String className = EntityUtils.toString(response.getEntity());
            
            // Load class safely and verify it implements a specific interface
            // ok: java-unsafe-reflection
            Class<?> clazz = Class.forName(className);
            if (Runnable.class.isAssignableFrom(clazz)) {
                Runnable instance = (Runnable) clazz.newInstance();
                instance.run();
            } else {
                System.out.println("Class does not implement required interface");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 6: Spark Framework with hardcoded class options
    public void good_case_6() {
        Spark.get("/api/load", (req, res) -> {
            String classOption = req.queryParams("option");
            try {
                String className;
                switch (classOption) {
                    case "list":
                        className = "java.util.ArrayList";
                        break;
                    case "map":
                        className = "java.util.HashMap";
                        break;
                    default:
                        return "Invalid option";
                }
                
                // ok: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                return clazz.getName();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        });
    }
    
    // Example 7: Javalin Framework with class name sanitization
    public void good_case_7() {
        Javalin app = Javalin.create().start(7000);
        app.get("/load-class", ctx -> {
            String className = ctx.queryParam("name");
            try {
                // Sanitize and validate class name
                if (className != null && 
                    className.matches("^[a-zA-Z0-9.]+$") && 
                    !className.contains("..")) {
                    
                    // Additional security check - only allow specific packages
                    if (className.startsWith("java.util.") || 
                        className.startsWith("com.myapp.model.")) {
                        // ok: java-unsafe-reflection
                        Class<?> clazz = Class.forName(className);
                        ctx.result("Loaded class: " + clazz.getName());
                    } else {
                        ctx.result("Package not allowed");
                    }
                } else {
                    ctx.result("Invalid class name format");
                }
            } catch (Exception e) {
                ctx.result("Error: " + e.getMessage());
            }
        });
    }
    
    // Example 8: Vert.x Framework with class loader restrictions
    public void good_case_8() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        // Create a custom class loader with restrictions
        ClassLoader restrictedLoader = new ClassLoader() {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (name.startsWith("java.util.") || name.startsWith("com.myapp.safe.")) {
                    return super.loadClass(name, resolve);
                }
                throw new ClassNotFoundException("Access denied to: " + name);
            }
        };
        
        router.get("/api/class").handler(routingContext -> {
            String className = routingContext.request().getParam("name");
            try {
                // ok: java-unsafe-reflection
                Class<?> clazz = Class.forName(className, true, restrictedLoader);
                routingContext.response().end("Loaded: " + clazz.getName());
            } catch (Exception e) {
                routingContext.response().end("Error: " + e.getMessage());
            }
        });
    }
    
    // Example 9: Jersey Framework with class mapping
    @Path("/api")
    public static class JerseyResourceSafe {
        private final Map<String, Class<?>> allowedClasses = new HashMap<>();
        
        public JerseyResourceSafe() {
            allowedClasses.put("list", java.util.ArrayList.class);
            allowedClasses.put("map", java.util.HashMap.class);
            allowedClasses.put("set", java.util.HashSet.class);
        }
        
        @GET
        @Path("/load-safe")
        public String good_case_9(@QueryParam("classKey") String classKey) {
            try {
                Class<?> clazz = allowedClasses.get(classKey);
                if (clazz != null) {
                    // ok: java-unsafe-reflection
                    Object instance = clazz.newInstance();
                    return "Loaded: " + instance.getClass().getName();
                } else {
                    return "Unknown class key";
                }
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
    
    // Example 10: Ratpack Framework with class validation
    public void good_case_10() throws Exception {
        RatpackServer.start(server -> server
            .handlers(chain -> chain
                .get("load-safe", ctx -> {
                    String className = ctx.getRequest().getQueryParams().get("name");
                    try {
                        // Validate against allowed packages and class name format
                        if (className != null && 
                            (className.startsWith("java.util.") || className.startsWith("com.myapp.model.")) &&
                            className.matches("^[a-zA-Z0-9.]+$")) {
                            
                            // ok: java-unsafe-reflection
                            Class<?> clazz = Class.forName(className);
                            ctx.render("Loaded: " + clazz.getName());
                        } else {
                            ctx.render("Class not allowed");
                        }
                    } catch (Exception e) {
                        ctx.render("Error: " + e.getMessage());
                    }
                })
            )
        );
    }
    
    // Example 11: Jetty Server with class name validation
    public void good_case_11() throws Exception {
        Server server = new Server(8080);
        server.setHandler(new AbstractHandler() {
            @Override
            public void handle(String target, Request baseRequest, 
                              javax.servlet.http.HttpServletRequest request, 
                              javax.servlet.http.HttpServletResponse response) throws IOException {
                String classKey = request.getParameter("classKey");
                
                // Map input to predefined classes
                Map<String, String> safeClasses = new HashMap<>();
                safeClasses.put("list", "java.util.ArrayList");
                safeClasses.put("map", "java.util.HashMap");
                safeClasses.put("set", "java.util.HashSet");
                
                String className = safeClasses.get(classKey);
                try {
                    if (className != null) {
                        // ok: java-unsafe-reflection
                        Class<?> clazz = Class.forName(className);
                        response.getWriter().println("Loaded: " + clazz.getName());
                    } else {
                        response.getWriter().println("Invalid class key");
                    }
                } catch (Exception e) {
                    response.getWriter().println("Error: " + e.getMessage());
                }
                baseRequest.setHandled(true);
            }
        });
        server.start();
    }
    
    // Example 12: AWS Lambda Function with safe class mapping
    public class SafeLambdaHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
        private final Map<String, String> allowedClasses = new HashMap<>();
        
        public SafeLambdaHandler() {
            allowedClasses.put("list", "java.util.ArrayList");
            allowedClasses.put("map", "java.util.HashMap");
        }
        
        @Override
        public APIGatewayProxyResponseEvent good_case_12(APIGatewayProxyRequestEvent input, Context context) {
            Map<String, String> queryParams = input.getQueryStringParameters();
            String classKey = queryParams.get("classKey");
            
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            try {
                String className = allowedClasses.get(classKey);
                if (className != null) {
                    // ok: java-unsafe-reflection
                    Class<?> clazz = Class.forName(className);
                    response.setBody("Loaded: " + clazz.getName());
                    response.setStatusCode(200);
                } else {
                    response.setBody("Invalid class key");
                    response.setStatusCode(400);
                }
            } catch (Exception e) {
                response.setBody("Error: " + e.getMessage());
                response.setStatusCode(500);
            }
            return response;
        }
    }
    
    // Example 13: Google Cloud Function with whitelist validation
    public class SafeCloudFunction implements HttpFunction {
        private final List<String> allowedClasses = new ArrayList<>();
        
        public SafeCloudFunction() {
            allowedClasses.add("java.util.ArrayList");
            allowedClasses.add("java.util.HashMap");
            allowedClasses.add("java.util.HashSet");
        }
        
        @Override
        public void good_case_13(HttpRequest request, HttpResponse response) throws Exception {
            String className = request.getFirstQueryParameter("class").orElse("");
            try {
                if (allowedClasses.contains(className)) {
                    // ok: java-unsafe-reflection
                    Class<?> clazz = Class.forName(className);
                    response.getWriter().write("Loaded: " + clazz.getName());
                } else {
                    response.getWriter().write("Class not allowed");
                }
            } catch (Exception e) {
                response.getWriter().write("Error: " + e.getMessage());
            }
        }
    }
    
    // Example 14: Spring RestTemplate with class name validation
    public void good_case_14() {
        RestTemplate restTemplate = new RestTemplateBuilder().build();
        String classInput = restTemplate.getForObject("https://example.com/api/class", String.class);
        
        try {
            // Validate the class name against a whitelist
            List<String> allowedClasses = new ArrayList<>();
            allowedClasses.add("java.util.ArrayList");
            allowedClasses.add("java.util.HashMap");
            
            if (allowedClasses.contains(classInput)) {
                // ok: java-unsafe-reflection
                Class<?> clazz = Class.forName(classInput);
                Object instance = clazz.newInstance();
                System.out.println("Created: " + instance);
            } else {
                System.out.println("Class not allowed: " + classInput);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Example 15: Retrofit API Client with class name validation
    public interface SafeApiService {
        @GET("/api/class")
        Call<String> getClassName();
    }
    
    public void good_case_15() {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://example.com")
            .build();
        
        SafeApiService service = retrofit.create(SafeApiService.class);
        try {
            String className = service.getClassName().execute().body();
            
            // Validate class name is from a safe package and has valid format
            if (className != null && 
                className.startsWith("com.myapp.safe.") && 
                className.matches("^[a-zA-Z0-9.]+$")) {
                
                // ok: java-unsafe-reflection
                Class<?> clazz = Class.forName(className);
                Object instance = clazz.newInstance();
                System.out.println("Created: " + instance);
            } else {
                System.out.println("Invalid or unsafe class name: " + className);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}