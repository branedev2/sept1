import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.Json;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import spark.Request;
import spark.Response;
import spark.Spark;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.glassfish.jersey.client.JerseyWebTarget;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Response.Status;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.URI;
import java.net.http.HttpClient;

// Security Issue: Jackson Insecure Deserialization (CWE-502)

// True Positive Examples (Vulnerable/Insecure Code)

public class JacksonInsecureDeserializationExamples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
    @RestController
    public static class BadCase1 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        @PostMapping("/api/data")
        public Map<String, Object> bad_case_1(@RequestBody String requestBody) throws IOException {
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(); // Deprecated but still used in older code
            
            // Deserialize data from HTTP request - vulnerable to attacks
            Map<String, Object> data = mapper.readValue(requestBody, Map.class);
            return data;
        }
    }
// {/fact}
    
    public static class BadCase2 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        public void bad_case_2(HttpServletRequest request) throws IOException {
            String jsonData = request.getParameter("data");
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
            
            // Process data from request parameter
            Object deserializedData = mapper.readValue(jsonData, Object.class);
            System.out.println("Processed data: " + deserializedData);
        }
    }
// {/fact}
    
    public static class BadCase3 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        public void bad_case_3(OkHttpClient client) throws IOException {
            Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .build();
                
            try (Response response = client.newCall(request).execute()) {
                String jsonData = response.body().string();
                
                ObjectMapper mapper = new ObjectMapper();
                // ruleid: java-jackson-insecure-deserialization
                mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator());
                
                // Deserialize data from external API
                Map<String, Object> result = mapper.readValue(jsonData, Map.class);
                processResult(result);
            }
        }
        
        private void processResult(Map<String, Object> result) {
            // Process the result
        }
    }
// {/fact}
    
    public static class BadCase4 implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
        @Override
        public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
            String body = input.getBody();
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.EVERYTHING);
            
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            try {
                // AWS Lambda deserializing user input
                Object data = mapper.readValue(body, Object.class);
                response.setStatusCode(200);
                response.setBody("Processed: " + mapper.writeValueAsString(data));
            } catch (Exception e) {
                response.setStatusCode(500);
                response.setBody("Error: " + e.getMessage());
            }
            return response;
        }
    }
    
    public static class BadCase5 extends AbstractVerticle {
        @Override
        public void start() {
            Router router = Router.router(vertx);
            router.route().handler(BodyHandler.create());
            
            router.post("/api/process").handler(this::handleRequest);
            
            vertx.createHttpServer()
                .requestHandler(router)
                .listen(8080);
        }
        
        private void handleRequest(RoutingContext context) {
            String body = context.getBodyAsString();
            
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE);
            
            try {
                // Vertx web framework deserializing request body
                Object data = mapper.readValue(body, Object.class);
                context.response()
                    .putHeader("content-type", "application/json")
                    .end(mapper.writeValueAsString(data));
            } catch (Exception e) {
                context.response()
                    .setStatusCode(500)
                    .end("Error: " + e.getMessage());
            }
        }
    }
    
    public static class BadCase6 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        public void bad_case_6() {
            Spark.post("/api/data", (Request request, Response response) -> {
                String body = request.body();
                
                ObjectMapper mapper = new ObjectMapper();
                // ruleid: java-jackson-insecure-deserialization
                mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator(), ObjectMapper.DefaultTyping.NON_FINAL);
                
                // Spark framework deserializing request body
                try {
                    Object result = mapper.readValue(body, Object.class);
                    return mapper.writeValueAsString(result);
                } catch (Exception e) {
                    response.status(500);
                    return "Error processing request: " + e.getMessage();
                }
            });
        }
    }
// {/fact}
    
    public static class BadCase7 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
            // Extract data from request headers
            String jsonData = request.getHeader("X-Custom-Data");
            
            XmlMapper xmlMapper = new XmlMapper();
            // ruleid: java-jackson-insecure-deserialization
            xmlMapper.enableDefaultTyping(); // XmlMapper extends ObjectMapper
            
            // Deserialize XML data from HTTP header
            Object result = xmlMapper.readValue(jsonData, Object.class);
            response.getWriter().write("Processed: " + result.toString());
        }
    }
// {/fact}
    
    public static class BadCase8 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        public void bad_case_8() {
            ResteasyClient client = new ResteasyClientBuilder().build();
            ResteasyWebTarget target = client.target("https://api.example.com/data");
            
            javax.ws.rs.core.Response response = target.request().get();
            String jsonData = response.readEntity(String.class);
            
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.JAVA_LANG_OBJECT);
            
            try {
                // RESTEasy client deserializing response data
                Object result = mapper.readValue(jsonData, Object.class);
                processData(result);
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
            }
        }
        
        private void processData(Object data) {
            // Process the data
        }
    }
// {/fact}
    
    public static class BadCase9 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        public void bad_case_9(String requestUrl) throws IOException, InterruptedException {
            java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(requestUrl))
                .build();
                
            java.net.http.HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
            String jsonData = response.body();
            
            YAMLMapper yamlMapper = new YAMLMapper();
            // ruleid: java-jackson-insecure-deserialization
            yamlMapper.enableDefaultTyping(); // YAMLMapper extends ObjectMapper
            
            // Java 11 HTTP client deserializing response as YAML
            Object result = yamlMapper.readValue(jsonData, Object.class);
            System.out.println("Processed data: " + result);
        }
    }
// {/fact}
    
    public static class BadCase10 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        public void bad_case_10() {
            Client client = JerseyClientBuilder.newClient();
            JerseyWebTarget target = (JerseyWebTarget) client.target("https://api.example.com/data");
            
            Invocation.Builder invocationBuilder = target.request(MediaType.APPLICATION_JSON);
            javax.ws.rs.core.Response response = invocationBuilder.get();
            
            if (response.getStatus() == Status.OK.getStatusCode()) {
                String jsonData = response.readEntity(String.class);
                
                ObjectMapper mapper = new ObjectMapper();
                // ruleid: java-jackson-insecure-deserialization
                mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator(), ObjectMapper.DefaultTyping.EVERYTHING);
                
                // Jersey client deserializing response
                try {
                    Map<String, Object> result = mapper.readValue(jsonData, new TypeReference<Map<String, Object>>() {});
                    processJerseyResponse(result);
                } catch (Exception e) {
                    System.err.println("Error processing response: " + e.getMessage());
                }
            }
        }
        
        private void processJerseyResponse(Map<String, Object> data) {
            // Process the data
        }
    }
// {/fact}
    
    public static class BadCase11 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        public Mono<ServerResponse> bad_case_11(ServerRequest request) {
            return request.bodyToMono(String.class)
                .flatMap(body -> {
                    ObjectMapper mapper = new ObjectMapper();
                    // ruleid: java-jackson-insecure-deserialization
                    mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
                    
                    try {
                        // Spring WebFlux deserializing request body
                        Object result = mapper.readValue(body, Object.class);
                        return ServerResponse.ok()
                            .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                            .bodyValue(result);
                    } catch (Exception e) {
                        return ServerResponse.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .bodyValue("Error: " + e.getMessage());
                    }
                });
        }
    }
// {/fact}
    
    public static class BadCase12 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        public CompletableFuture<String> bad_case_12(String url) {
            WebClient webClient = WebClient.create();
            
            return webClient.get()
                .uri(url)
                .retrieve()
                .bodyToMono(String.class)
                .flatMap(jsonData -> {
                    ObjectMapper mapper = new ObjectMapper();
                    // ruleid: java-jackson-insecure-deserialization
                    mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator(), ObjectMapper.DefaultTyping.JAVA_LANG_OBJECT);
                    
                    try {
                        // Spring WebClient deserializing response
                        Object result = mapper.readValue(jsonData, Object.class);
                        return Mono.just("Processed: " + result.toString());
                    } catch (Exception e) {
                        return Mono.error(e);
                    }
                })
                .toFuture();
        }
    }
// {/fact}
    
    public static class BadCase13 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        public void bad_case_13(HttpServletRequest request) throws IOException {
            // Extract data from request cookies
            javax.servlet.http.Cookie[] cookies = request.getCookies();
            String jsonData = null;
            
            for (javax.servlet.http.Cookie cookie : cookies) {
                if ("userData".equals(cookie.getName())) {
                    jsonData = cookie.getValue();
                    break;
                }
            }
            
            if (jsonData != null) {
                ObjectMapper mapper = new ObjectMapper();
                // ruleid: java-jackson-insecure-deserialization
                mapper.enableDefaultTyping();
                
                // Deserialize data from HTTP cookie
                Object userData = mapper.readValue(jsonData, Object.class);
                System.out.println("User data: " + userData);
            }
        }
    }
// {/fact}
    
    public static class BadCase14 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        public ResponseEntity<Object> bad_case_14(@RequestParam String jsonData) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                // ruleid: java-jackson-insecure-deserialization
                mapper.activateDefaultTyping(mapper.getPolymorphicTypeValidator(), ObjectMapper.DefaultTyping.NON_FINAL);
                
                // Deserialize data from query parameter
                Object result = mapper.readValue(jsonData, Object.class);
                return ResponseEntity.ok(result);
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: " + e.getMessage());
            }
        }
    }
// {/fact}
    
    public static class BadCase15 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
        public void bad_case_15(HttpServletRequest request) throws IOException {
            // Get JSON data from multipart form
            String jsonData = request.getPart("userData").getInputStream().toString();
            
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jackson-insecure-deserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.EVERYTHING);
            
            // Deserialize data from multipart form
            Object userData = mapper.readValue(jsonData, Object.class);
            System.out.println("Processed user data: " + userData);
        }
    }
// {/fact}
    
    // True Negative Examples (Safe/Secure Code)
    
    @RestController
    public static class GoodCase1 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        @PostMapping("/api/data")
        public Map<String, Object> good_case_1(@RequestBody String requestBody) throws IOException {
            ObjectMapper mapper = new ObjectMapper();
            // Using explicit type information instead of default typing
            // ok: java-jackson-insecure-deserialization
            Map<String, Object> data = mapper.readValue(requestBody, Map.class);
            return data;
        }
    }
// {/fact}
    
    public static class GoodCase2 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        public void good_case_2(HttpServletRequest request) throws IOException {
            String jsonData = request.getParameter("data");
            ObjectMapper mapper = new ObjectMapper();
            
            // Using a specific class instead of enabling default typing
            // ok: java-jackson-insecure-deserialization
            HashMap<String, String> deserializedData = mapper.readValue(jsonData, HashMap.class);
            System.out.println("Processed data: " + deserializedData);
        }
    }
// {/fact}
    
    public static class GoodCase3 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        public void good_case_3(OkHttpClient client) throws IOException {
            Request request = new Request.Builder()
                .url("https://api.example.com/data")
                .build();
                
            try (Response response = client.newCall(request).execute()) {
                String jsonData = response.body().string();
                
                ObjectMapper mapper = new ObjectMapper();
                // Using a specific type reference instead of default typing
                // ok: java-jackson-insecure-deserialization
                Map<String, Object> result = mapper.readValue(jsonData, new TypeReference<Map<String, Object>>() {});
                processResult(result);
            }
        }
        
        private void processResult(Map<String, Object> result) {
            // Process the result
        }
    }
// {/fact}
    
    public static class GoodCase4 implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
        @Override
        public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
            String body = input.getBody();
            ObjectMapper mapper = new ObjectMapper();
            
            // Disable default typing explicitly
            // ok: java-jackson-insecure-deserialization
            mapper.disableDefaultTyping();
            
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            try {
                // AWS Lambda deserializing user input with specific type
                Map<String, Object> data = mapper.readValue(body, Map.class);
                response.setStatusCode(200);
                response.setBody("Processed: " + mapper.writeValueAsString(data));
            } catch (Exception e) {
                response.setStatusCode(500);
                response.setBody("Error: " + e.getMessage());
            }
            return response;
        }
    }
    
    public static class GoodCase5 extends AbstractVerticle {
        @Override
        public void start() {
            Router router = Router.router(vertx);
            router.route().handler(BodyHandler.create());
            
            router.post("/api/process").handler(this::handleRequest);
            
            vertx.createHttpServer()
                .requestHandler(router)
                .listen(8080);
        }
        
        private void handleRequest(RoutingContext context) {
            String body = context.getBodyAsString();
            
            ObjectMapper mapper = new ObjectMapper();
            // Using a restricted polymorphic type validator
            PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(MyDataClass.class)
                .build();
            
            // ok: java-jackson-insecure-deserialization
            mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
            
            try {
                // Vertx web framework deserializing request body with validation
                MyDataClass data = mapper.readValue(body, MyDataClass.class);
                context.response()
                    .putHeader("content-type", "application/json")
                    .end(mapper.writeValueAsString(data));
            } catch (Exception e) {
                context.response()
                    .setStatusCode(500)
                    .end("Error: " + e.getMessage());
            }
        }
        
        private static class MyDataClass {
            private String name;
            private int value;
            
            public String getName() { return name; }
            public void setName(String name) { this.name = name; }
            public int getValue() { return value; }
            public void setValue(int value) { this.value = value; }
        }
    }
    
    public static class GoodCase6 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        public void good_case_6() {
            Spark.post("/api/data", (Request request, Response response) -> {
                String body = request.body();
                
                ObjectMapper mapper = new ObjectMapper();
                // Using specific class instead of default typing
                // ok: java-jackson-insecure-deserialization
                Map<String, Object> result = mapper.readValue(body, Map.class);
                return mapper.writeValueAsString(result);
            });
        }
    }
// {/fact}
    
    public static class GoodCase7 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
            // Extract data from request headers
            String jsonData = request.getHeader("X-Custom-Data");
            
            XmlMapper xmlMapper = new XmlMapper();
            // Using a specific class instead of default typing
            // ok: java-jackson-insecure-deserialization
            HashMap<String, String> result = xmlMapper.readValue(jsonData, HashMap.class);
            response.getWriter().write("Processed: " + result.toString());
        }
    }
// {/fact}
    
    public static class GoodCase8 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        public void good_case_8() {
            ResteasyClient client = new ResteasyClientBuilder().build();
            ResteasyWebTarget target = client.target("https://api.example.com/data");
            
            javax.ws.rs.core.Response response = target.request().get();
            String jsonData = response.readEntity(String.class);
            
            ObjectMapper mapper = new ObjectMapper();
            // Configure to use a safe subset of classes
            PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfSubType("com.mycompany.model")
                .build();
            
            // ok: java-jackson-insecure-deserialization
            mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
            
            try {
                // RESTEasy client deserializing response data with validation
                Map<String, Object> result = mapper.readValue(jsonData, Map.class);
                processData(result);
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
            }
        }
        
        private void processData(Object data) {
            // Process the data
        }
    }
// {/fact}
    
    public static class GoodCase9 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        public void good_case_9(String requestUrl) throws IOException, InterruptedException {
            java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(requestUrl))
                .build();
                
            java.net.http.HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
            String jsonData = response.body();
            
            YAMLMapper yamlMapper = new YAMLMapper();
            // Explicitly disable default typing
            // ok: java-jackson-insecure-deserialization
            yamlMapper.disableDefaultTyping();
            
            // Java 11 HTTP client deserializing response as YAML with specific type
            Map<String, Object> result = yamlMapper.readValue(jsonData, Map.class);
            System.out.println("Processed data: " + result);
        }
    }
// {/fact}
    
    public static class GoodCase10 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        public void good_case_10() {
            Client client = JerseyClientBuilder.newClient();
            JerseyWebTarget target = (JerseyWebTarget) client.target("https://api.example.com/data");
            
            Invocation.Builder invocationBuilder = target.request(MediaType.APPLICATION_JSON);
            javax.ws.rs.core.Response response = invocationBuilder.get();
            
            if (response.getStatus() == Status.OK.getStatusCode()) {
                String jsonData = response.readEntity(String.class);
                
                ObjectMapper mapper = new ObjectMapper();
                // Using a specific class with no default typing
                // ok: java-jackson-insecure-deserialization
                List<Map<String, Object>> result = mapper.readValue(jsonData, new TypeReference<List<Map<String, Object>>>() {});
                processJerseyResponse(result);
            }
        }
        
        private void processJerseyResponse(List<Map<String, Object>> data) {
            // Process the data
        }
    }
// {/fact}
    
    public static class GoodCase11 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        public Mono<ServerResponse> good_case_11(ServerRequest request) {
            return request.bodyToMono(String.class)
                .flatMap(body -> {
                    ObjectMapper mapper = new ObjectMapper();
                    // Configure mapper to be safe
                    // ok: java-jackson-insecure-deserialization
                    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
                    
                    try {
                        // Spring WebFlux deserializing request body with specific type
                        Map<String, Object> result = mapper.readValue(body, Map.class);
                        return ServerResponse.ok()
                            .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                            .bodyValue(result);
                    } catch (Exception e) {
                        return ServerResponse.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .bodyValue("Error: " + e.getMessage());
                    }
                });
        }
    }
// {/fact}
    
    public static class GoodCase12 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        public CompletableFuture<String> good_case_12(String url) {
            WebClient webClient = WebClient.create();
            
            return webClient.get()
                .uri(url)
                .retrieve()
                .bodyToMono(String.class)
                .flatMap(jsonData -> {
                    ObjectMapper mapper = new ObjectMapper();
                    // Using a specific class with no default typing
                    // ok: java-jackson-insecure-deserialization
                    try {
                        List<String> result = mapper.readValue(jsonData, new TypeReference<List<String>>() {});
                        return Mono.just("Processed: " + result.toString());
                    } catch (Exception e) {
                        return Mono.error(e);
                    }
                })
                .toFuture();
        }
    }
// {/fact}
    
    public static class GoodCase13 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        public void good_case_13(HttpServletRequest request) throws IOException {
            // Extract data from request cookies
            javax.servlet.http.Cookie[] cookies = request.getCookies();
            String jsonData = null;
            
            for (javax.servlet.http.Cookie cookie : cookies) {
                if ("userData".equals(cookie.getName())) {
                    jsonData = cookie.getValue();
                    break;
                }
            }
            
            if (jsonData != null) {
                ObjectMapper mapper = new ObjectMapper();
                // Using a specific class with validation
                // ok: java-jackson-insecure-deserialization
                UserData userData = mapper.readValue(jsonData, UserData.class);
                System.out.println("User data: " + userData);
            }
        }
        
        private static class UserData {
            private String username;
            private String email;
            
            public String getUsername() { return username; }
            public void setUsername(String username) { this.username = username; }
            public String getEmail() { return email; }
            public void setEmail(String email) { this.email = email; }
            
            @Override
            public String toString() {
                return "UserData{username='" + username + "', email='" + email + "'}";
            }
        }
    }
// {/fact}
    
    public static class GoodCase14 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        public ResponseEntity<Object> good_case_14(@RequestParam String jsonData) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                // Using a specific class with no default typing
                // ok: java-jackson-insecure-deserialization
                Map<String, String> result = mapper.readValue(jsonData, new TypeReference<Map<String, String>>() {});
                return ResponseEntity.ok(result);
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: " + e.getMessage());
            }
        }
    }
// {/fact}
    
    public static class GoodCase15 {
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
        public void good_case_15(HttpServletRequest request) throws IOException {
            // Get JSON data from multipart form
            String jsonData = request.getPart("userData").getInputStream().toString();
            
            ObjectMapper mapper = new ObjectMapper();
            // Using a safe polymorphic type validator
            PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfSubType("com.myapp.model")
                .allowIfSubType("java.util.ArrayList")
                .allowIfSubType("java.util.HashMap")
                .build();
                
            // ok: java-jackson-insecure-deserialization
            mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
            
            // Deserialize data from multipart form with validation
            Map<String, Object> userData = mapper.readValue(jsonData, Map.class);
            System.out.println("Processed user data: " + userData);
        }
    }
// {/fact}
}