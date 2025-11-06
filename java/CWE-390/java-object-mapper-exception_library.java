import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.glassfish.jersey.client.JerseyClient;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;
import org.asynchttpclient.Response;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.springframework.cloud.openfeign.FeignClient;
import feign.RequestLine;
import feign.Feign;
import feign.jackson.JacksonDecoder;
import kong.unirest.Unirest;
import kong.unirest.HttpResponse;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.codec.BodyCodec;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.quarkus.rest.client.reactive.QuarkusRestClientBuilder;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.logging.Logger;
import java.util.logging.Level;

// Security Issue: Swallowing exceptions thrown by ObjectMapper.readValue() can hide important error information
// and lead to unexpected behavior, security vulnerabilities, or application instability.

// True Positive Examples (Vulnerable/Insecure Code)

public class ObjectMapperExceptionHandlingExamples {
    private static final Logger logger = Logger.getLogger(ObjectMapperExceptionHandlingExamples.class.getName());
    private static final ObjectMapper mapper = new ObjectMapper();
    
    // True Positive Examples (Vulnerable/Insecure Code)
    
    // Spring Web MVC example
    @RestController
    public static class BadCase1 {
        @PostMapping("/api/users")
        public ResponseEntity<String> processUserData(@RequestBody String requestBody) {
            User user = null;
            try {
                // ruleid: java-object-mapper-exception
                user = new ObjectMapper().readValue(requestBody, User.class);
            } catch (IOException e) {
                // Exception is caught but completely ignored
            }
            
            return ResponseEntity.ok("User processed");
        }
        
        private static class User {
            private String name;
            private String email;
            // Getters and setters omitted for brevity
        }
    }
    
    // OkHttp client example
    public static void badCase2() {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/data")
            .build();
            
        try (Response response = client.newCall(request).execute()) {
            String responseBody = response.body().string();
            try {
                // ruleid: java-object-mapper-exception
                Map<String, Object> data = new ObjectMapper().readValue(responseBody, 
                    new TypeReference<Map<String, Object>>() {});
            } catch (IOException e) {
                // Exception caught but swallowed
            }
            System.out.println("Data processed");
        } catch (IOException e) {
            System.out.println("Error making HTTP request");
        }
    }
    
    // Apache HttpClient example
    public static void badCase3() {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("https://api.example.com/products");
            org.apache.http.HttpResponse response = httpClient.execute(request);
            String responseBody = EntityUtils.toString(response.getEntity());
            
            try {
                // ruleid: java-object-mapper-exception
                List<Product> products = new ObjectMapper().readValue(responseBody,
                    new TypeReference<List<Product>>() {});
            } catch (Exception e) {
                // Generic exception caught and swallowed
            }
        } catch (IOException e) {
            System.out.println("HTTP request failed");
        }
    }
    
    // Jersey Client example
    public static void badCase4() {
        JerseyClient client = JerseyClientBuilder.createClient();
        String response = client.target("https://api.example.com/orders")
            .request()
            .get(String.class);
            
        try {
            // ruleid: java-object-mapper-exception
            Order[] orders = new ObjectMapper().readValue(response, Order[].class);
        } catch (IOException e) {
            // Exception caught and ignored
        }
    }
    
    // AsyncHttpClient example
    public static void badCase5() {
        AsyncHttpClient client = Dsl.asyncHttpClient();
        try {
            org.asynchttpclient.Response response = client.prepareGet("https://api.example.com/config")
                .execute()
                .toCompletableFuture()
                .get();
                
            String responseBody = response.getResponseBody();
            try {
                // ruleid: java-object-mapper-exception
                Config config = new ObjectMapper().readValue(responseBody, Config.class);
            } catch (IOException e) {
                // Exception caught and swallowed
            }
        } catch (Exception e) {
            System.out.println("Request failed");
        } finally {
            client.close();
        }
    }
    
    // Google HTTP Client example
    public static void badCase6() {
        try {
            HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
            HttpRequest request = requestFactory.buildGetRequest(
                new GenericUrl("https://api.example.com/settings"));
            String responseBody = request.execute().parseAsString();
            
            try {
                // ruleid: java-object-mapper-exception
                Settings settings = new ObjectMapper().readValue(responseBody, Settings.class);
            } catch (IOException e) {
                // Exception caught but ignored
            }
        } catch (IOException e) {
            System.out.println("HTTP request failed");
        }
    }
    
    // AWS Lambda API Gateway handler
    public static class BadCase7 implements RequestHandler<APIGatewayProxyRequestEvent, String> {
        @Override
        public String handleRequest(APIGatewayProxyRequestEvent input, Context context) {
            String body = input.getBody();
            try {
                // ruleid: java-object-mapper-exception
                UserRequest userRequest = new ObjectMapper().readValue(body, UserRequest.class);
            } catch (IOException e) {
                // Exception caught and swallowed
            }
            return "Request processed";
        }
        
        private static class UserRequest {
            private String action;
            private Map<String, String> parameters;
            // Getters and setters omitted for brevity
        }
    }
    
    // Feign client example
    public static void badCase8() {
        @FeignClient(name = "example-service")
        interface ExampleClient {
            @RequestLine("GET /api/data")
            String getData();
        }
        
        ExampleClient client = Feign.builder()
            .decoder(new JacksonDecoder())
            .target(ExampleClient.class, "https://api.example.com");
            
        String response = client.getData();
        try {
            // ruleid: java-object-mapper-exception
            DataResponse dataResponse = new ObjectMapper().readValue(response, DataResponse.class);
        } catch (IOException e) {
            // Exception caught and ignored
        }
    }
    
    // Unirest example
    public static void badCase9() {
        HttpResponse<String> response = Unirest.get("https://api.example.com/metrics")
            .asString();
            
        try {
            // ruleid: java-object-mapper-exception
            Metrics metrics = new ObjectMapper().readValue(response.getBody(), Metrics.class);
        } catch (IOException e) {
            // Exception caught and swallowed
        }
    }
    
    // RESTEasy client example
    public static void badCase10() {
        ResteasyClient client = new ResteasyClientBuilder().build();
        ResteasyWebTarget target = client.target("https://api.example.com/stats");
        String response = target.request().get(String.class);
        
        try {
            // ruleid: java-object-mapper-exception
            Statistics stats = new ObjectMapper().readValue(response, Statistics.class);
        } catch (IOException e) {
            // Exception caught but ignored
        } finally {
            client.close();
        }
    }
    
    // Vert.x Web Client example
    public static void badCase11() {
        Vertx vertx = Vertx.vertx();
        WebClient client = WebClient.create(vertx);
        
        client.get(443, "api.example.com", "/users")
            .ssl(true)
            .send(ar -> {
                if (ar.succeeded()) {
                    String responseBody = ar.result().bodyAsString();
                    try {
                        // ruleid: java-object-mapper-exception
                        UserList users = new ObjectMapper().readValue(responseBody, UserList.class);
                    } catch (IOException e) {
                        // Exception caught and swallowed
                    }
                }
            });
    }
    
    // Micronaut HTTP client example
    public static void badCase12() {
        @Client("https://api.example.com")
        interface ApiClient {
            @io.micronaut.http.annotation.Get("/products")
            String getProducts();
        }
        
        // Assuming client is injected
        ApiClient client = null; // In real code this would be injected
        String response = client.getProducts();
        
        try {
            // ruleid: java-object-mapper-exception
            ProductList products = new ObjectMapper().readValue(response, ProductList.class);
        } catch (IOException e) {
            // Exception caught and ignored
        }
    }
    
    // Quarkus REST client example
    public static void badCase13() {
        @RegisterRestClient(baseUri = "https://api.example.com")
        interface ApiClient {
            @javax.ws.rs.GET
            @javax.ws.rs.Path("/categories")
            String getCategories();
        }
        
        ApiClient client = QuarkusRestClientBuilder.newBuilder()
            .baseUri(URI.create("https://api.example.com"))
            .build(ApiClient.class);
            
        String response = client.getCategories();
        try {
            // ruleid: java-object-mapper-exception
            CategoryList categories = new ObjectMapper().readValue(response, CategoryList.class);
        } catch (IOException e) {
            // Exception caught and swallowed
        }
    }
    
    // Java 11 HTTP Client example
    public static void badCase14() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.com/inventory"))
            .build();
            
        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            try {
                // ruleid: java-object-mapper-exception
                Inventory inventory = new ObjectMapper().readValue(response.body(), Inventory.class);
            } catch (IOException e) {
                // Exception caught and ignored
            }
        } catch (Exception e) {
            System.out.println("Request failed");
        }
    }
    
    // Servlet API example
    public static void badCase15(HttpServletRequest request) {
        try {
            StringBuilder buffer = new StringBuilder();
            String line;
            java.io.BufferedReader reader = request.getReader();
            while ((line = reader.readLine()) != null) {
                buffer.append(line);
            }
            String requestBody = buffer.toString();
            
            try {
                // ruleid: java-object-mapper-exception
                Command command = new ObjectMapper().readValue(requestBody, Command.class);
            } catch (IOException e) {
                // Exception caught and swallowed
            }
        } catch (IOException e) {
            System.out.println("Error reading request");
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Spring Web MVC example - proper exception handling
    @RestController
    public static class GoodCase1 {
        @PostMapping("/api/users")
        public ResponseEntity<String> processUserData(@RequestBody String requestBody) {
            try {
                // ok: java-object-mapper-exception
                User user = new ObjectMapper().readValue(requestBody, User.class);
                return ResponseEntity.ok("User processed");
            } catch (IOException e) {
                logger.log(Level.WARNING, "Failed to parse user data", e);
                return ResponseEntity.badRequest().body("Invalid user data format");
            }
        }
        
        private static class User {
            private String name;
            private String email;
            // Getters and setters omitted for brevity
        }
    }
    
    // OkHttp client example - proper exception handling
    public static void goodCase2() {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/data")
            .build();
            
        try (Response response = client.newCall(request).execute()) {
            String responseBody = response.body().string();
            try {
                // ok: java-object-mapper-exception
                Map<String, Object> data = new ObjectMapper().readValue(responseBody, 
                    new TypeReference<Map<String, Object>>() {});
                System.out.println("Data processed");
            } catch (IOException e) {
                logger.log(Level.SEVERE, "Failed to parse response data", e);
                throw new RuntimeException("Data parsing failed", e);
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error making HTTP request", e);
        }
    }
    
    // Apache HttpClient example - proper exception handling
    public static void goodCase3() {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("https://api.example.com/products");
            org.apache.http.HttpResponse response = httpClient.execute(request);
            String responseBody = EntityUtils.toString(response.getEntity());
            
            try {
                // ok: java-object-mapper-exception
                List<Product> products = new ObjectMapper().readValue(responseBody,
                    new TypeReference<List<Product>>() {});
                System.out.println("Found " + products.size() + " products");
            } catch (IOException e) {
                logger.log(Level.WARNING, "Failed to parse product data", e);
                throw new RuntimeException("Product data parsing failed", e);
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "HTTP request failed", e);
        }
    }
    
    // Jersey Client example - proper exception handling
    public static void goodCase4() {
        JerseyClient client = JerseyClientBuilder.createClient();
        String response = client.target("https://api.example.com/orders")
            .request()
            .get(String.class);
            
        try {
            // ok: java-object-mapper-exception
            Order[] orders = new ObjectMapper().readValue(response, Order[].class);
            System.out.println("Processed " + orders.length + " orders");
        } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to parse orders", e);
            throw new RuntimeException("Order parsing failed", e);
        }
    }
    
    // AsyncHttpClient example - proper exception handling
    public static void goodCase5() {
        AsyncHttpClient client = Dsl.asyncHttpClient();
        try {
            org.asynchttpclient.Response response = client.prepareGet("https://api.example.com/config")
                .execute()
                .toCompletableFuture()
                .get();
                
            String responseBody = response.getResponseBody();
            try {
                // ok: java-object-mapper-exception
                Config config = new ObjectMapper().readValue(responseBody, Config.class);
                System.out.println("Config loaded: " + config);
            } catch (IOException e) {
                logger.log(Level.SEVERE, "Failed to parse configuration", e);
                throw new RuntimeException("Configuration parsing failed", e);
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Request failed", e);
        } finally {
            client.close();
        }
    }
    
    // Google HTTP Client example - proper exception handling
    public static void goodCase6() {
        try {
            HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
            HttpRequest request = requestFactory.buildGetRequest(
                new GenericUrl("https://api.example.com/settings"));
            String responseBody = request.execute().parseAsString();
            
            try {
                // ok: java-object-mapper-exception
                Settings settings = new ObjectMapper().readValue(responseBody, Settings.class);
                System.out.println("Settings loaded: " + settings);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Failed to parse settings", e);
                throw new RuntimeException("Settings parsing failed", e);
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "HTTP request failed", e);
        }
    }
    
    // AWS Lambda API Gateway handler - proper exception handling
    public static class GoodCase7 implements RequestHandler<APIGatewayProxyRequestEvent, String> {
        @Override
        public String handleRequest(APIGatewayProxyRequestEvent input, Context context) {
            String body = input.getBody();
            try {
                // ok: java-object-mapper-exception
                UserRequest userRequest = new ObjectMapper().readValue(body, UserRequest.class);
                return "Request processed: " + userRequest.getAction();
            } catch (IOException e) {
                context.getLogger().log("Failed to parse request: " + e.getMessage());
                return "Error: Invalid request format";
            }
        }
        
        private static class UserRequest {
            private String action;
            private Map<String, String> parameters;
            
            public String getAction() {
                return action;
            }
            // Other getters and setters omitted for brevity
        }
    }
    
    // Feign client example - proper exception handling
    public static void goodCase8() {
        @FeignClient(name = "example-service")
        interface ExampleClient {
            @RequestLine("GET /api/data")
            String getData();
        }
        
        ExampleClient client = Feign.builder()
            .decoder(new JacksonDecoder())
            .target(ExampleClient.class, "https://api.example.com");
            
        String response = client.getData();
        try {
            // ok: java-object-mapper-exception
            DataResponse dataResponse = new ObjectMapper().readValue(response, DataResponse.class);
            System.out.println("Data response: " + dataResponse);
        } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to parse data response", e);
            throw new RuntimeException("Data response parsing failed", e);
        }
    }
    
    // Unirest example - proper exception handling
    public static void goodCase9() {
        HttpResponse<String> response = Unirest.get("https://api.example.com/metrics")
            .asString();
            
        try {
            // ok: java-object-mapper-exception
            Metrics metrics = new ObjectMapper().readValue(response.getBody(), Metrics.class);
            System.out.println("Metrics loaded: " + metrics);
        } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to parse metrics", e);
            throw new RuntimeException("Metrics parsing failed", e);
        }
    }
    
    // RESTEasy client example - proper exception handling
    public static void goodCase10() {
        ResteasyClient client = new ResteasyClientBuilder().build();
        ResteasyWebTarget target = client.target("https://api.example.com/stats");
        String response = target.request().get(String.class);
        
        try {
            // ok: java-object-mapper-exception
            Statistics stats = new ObjectMapper().readValue(response, Statistics.class);
            System.out.println("Statistics loaded: " + stats);
        } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to parse statistics", e);
            throw new RuntimeException("Statistics parsing failed", e);
        } finally {
            client.close();
        }
    }
    
    // Vert.x Web Client example - proper exception handling
    public static void goodCase11() {
        Vertx vertx = Vertx.vertx();
        WebClient client = WebClient.create(vertx);
        
        client.get(443, "api.example.com", "/users")
            .ssl(true)
            .send(ar -> {
                if (ar.succeeded()) {
                    String responseBody = ar.result().bodyAsString();
                    try {
                        // ok: java-object-mapper-exception
                        UserList users = new ObjectMapper().readValue(responseBody, UserList.class);
                        System.out.println("User list loaded: " + users);
                    } catch (IOException e) {
                        logger.log(Level.WARNING, "Failed to parse user list", e);
                        // Properly handle the exception in async context
                        vertx.runOnContext(v -> {
                            throw new RuntimeException("User list parsing failed", e);
                        });
                    }
                }
            });
    }
    
    // Micronaut HTTP client example - proper exception handling
    public static void goodCase12() {
        @Client("https://api.example.com")
        interface ApiClient {
            @io.micronaut.http.annotation.Get("/products")
            String getProducts();
        }
        
        // Assuming client is injected
        ApiClient client = null; // In real code this would be injected
        String response = client.getProducts();
        
        try {
            // ok: java-object-mapper-exception
            ProductList products = new ObjectMapper().readValue(response, ProductList.class);
            System.out.println("Product list loaded: " + products);
        } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to parse product list", e);
            throw new RuntimeException("Product list parsing failed", e);
        }
    }
    
    // Quarkus REST client example - proper exception handling
    public static void goodCase13() {
        @RegisterRestClient(baseUri = "https://api.example.com")
        interface ApiClient {
            @javax.ws.rs.GET
            @javax.ws.rs.Path("/categories")
            String getCategories();
        }
        
        ApiClient client = QuarkusRestClientBuilder.newBuilder()
            .baseUri(URI.create("https://api.example.com"))
            .build(ApiClient.class);
            
        String response = client.getCategories();
        try {
            // ok: java-object-mapper-exception
            CategoryList categories = new ObjectMapper().readValue(response, CategoryList.class);
            System.out.println("Category list loaded: " + categories);
        } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to parse category list", e);
            throw new RuntimeException("Category list parsing failed", e);
        }
    }
    
    // Java 11 HTTP Client example - proper exception handling
    public static void goodCase14() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.com/inventory"))
            .build();
            
        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            try {
                // ok: java-object-mapper-exception
                Inventory inventory = new ObjectMapper().readValue(response.body(), Inventory.class);
                System.out.println("Inventory loaded: " + inventory);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Failed to parse inventory data", e);
                throw new RuntimeException("Inventory data parsing failed", e);
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Request failed", e);
        }
    }
    
    // Servlet API example - proper exception handling
    public static void goodCase15(HttpServletRequest request) {
        try {
            StringBuilder buffer = new StringBuilder();
            String line;
            java.io.BufferedReader reader = request.getReader();
            while ((line = reader.readLine()) != null) {
                buffer.append(line);
            }
            String requestBody = buffer.toString();
            
            try {
                // ok: java-object-mapper-exception
                Command command = new ObjectMapper().readValue(requestBody, Command.class);
                System.out.println("Command processed: " + command);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Failed to parse command", e);
                throw new RuntimeException("Command parsing failed", e);
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error reading request", e);
        }
    }
    
    // Model classes used in examples
    private static class Product {}
    private static class Order {}
    private static class Config {}
    private static class Settings {}
    private static class DataResponse {}
    private static class Metrics {}
    private static class Statistics {}
    private static class UserList {}
    private static class ProductList {}
    private static class CategoryList {}
    private static class Inventory {}
    private static class Command {}
}