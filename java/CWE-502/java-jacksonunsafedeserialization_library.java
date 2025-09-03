import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonProcessingException;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import feign.Feign;
import feign.jackson.JacksonDecoder;

import org.glassfish.jersey.client.JerseyClient;
import org.glassfish.jersey.client.JerseyClientBuilder;

import org.apache.cxf.jaxrs.client.WebClient;

import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;

import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;

import spark.Request;
import spark.Response;
import spark.Spark;

import ratpack.server.RatpackServer;
import ratpack.handling.Context;

import io.javalin.Javalin;
import io.javalin.http.Context;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;

import com.linecorp.armeria.server.Server;
import com.linecorp.armeria.server.ServerBuilder;
import com.linecorp.armeria.common.HttpResponse;

import org.springframework.cloud.openfeign.FeignClient;

// Security Issue: Jackson Unsafe Deserialization through enableDefaultTyping()

// True Positive Examples (Vulnerable/Insecure Code)
class JacksonUnsafeDeserialization {

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public static void bad_case_1(HttpServletRequest request) {
        try {
            String jsonData = request.getParameter("data");
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jacksonunsafedeserialization
            mapper.enableDefaultTyping(); // Vulnerable: enables polymorphic type handling without restrictions
            Object obj = mapper.readValue(jsonData, Object.class);
            System.out.println("Deserialized object: " + obj);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @RestController
    public static class bad_case_2 {
        @PostMapping("/process")
        public ResponseEntity<String> processData(@RequestBody String requestBody) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                // ruleid: java-jacksonunsafedeserialization
                mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.JAVA_LANG_OBJECT);
                Map<String, Object> data = mapper.readValue(requestBody, Map.class);
                return ResponseEntity.ok("Processed: " + data.size() + " items");
            } catch (Exception e) {
                return ResponseEntity.badRequest().body("Error: " + e.getMessage());
            }
        }
    }

    public static void bad_case_3() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.route().handler(BodyHandler.create());
        router.post("/api/data").handler(ctx -> {
            String body = ctx.getBodyAsString();
            try {
                ObjectMapper mapper = new ObjectMapper();
                // ruleid: java-jacksonunsafedeserialization
                mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
                Object result = mapper.readValue(body, Object.class);
                ctx.response().end("Processed data successfully");
            } catch (Exception e) {
                ctx.response().setStatusCode(400).end("Error processing data");
            }
        });
        
        vertx.createHttpServer().requestHandler(router).listen(8080);
    }

    public static void bad_case_4() {
        Javalin app = Javalin.create().start(7000);
        app.post("/api/process", ctx -> {
            String requestBody = ctx.body();
            try {
                ObjectMapper mapper = new ObjectMapper();
                // ruleid: java-jacksonunsafedeserialization
                mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE);
                List<Object> items = mapper.readValue(requestBody, List.class);
                ctx.result("Processed " + items.size() + " items");
            } catch (Exception e) {
                ctx.status(400).result("Error: " + e.getMessage());
            }
        });
    }

    public static void bad_case_5() {
        try {
            RatpackServer.start(server -> server
                .handlers(chain -> chain
                    .post("api/data", ctx -> {
                        ctx.getRequest().getBody().then(body -> {
                            String data = body.getText();
                            try {
                                ObjectMapper mapper = new ObjectMapper();
                                // ruleid: java-jacksonunsafedeserialization
                                mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
                                Object result = mapper.readValue(data, Object.class);
                                ctx.render("Processed successfully");
                            } catch (Exception e) {
                                ctx.render("Error: " + e.getMessage());
                            }
                        });
                    })
                )
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @RouteBase(path = "/api")
    public static class bad_case_6 {
        @Route(path = "process", methods = io.vertx.core.http.HttpMethod.POST)
        void processData(io.vertx.ext.web.RoutingContext ctx) {
            String body = ctx.getBodyAsString();
            try {
                ObjectMapper mapper = new ObjectMapper();
                // ruleid: java-jacksonunsafedeserialization
                mapper.enableDefaultTyping();
                Map<String, Object> data = mapper.readValue(body, Map.class);
                ctx.response().end("Processed data with " + data.size() + " entries");
            } catch (Exception e) {
                ctx.response().setStatusCode(400).end("Error: " + e.getMessage());
            }
        }
    }

    public static void bad_case_7() {
        Spark.post("/api/data", (Request request, Response response) -> {
            String body = request.body();
            try {
                ObjectMapper mapper = new ObjectMapper();
                // ruleid: java-jacksonunsafedeserialization
                mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.JAVA_LANG_OBJECT);
                Object data = mapper.readValue(body, Object.class);
                return "Data processed successfully";
            } catch (Exception e) {
                response.status(400);
                return "Error: " + e.getMessage();
            }
        });
    }

    @Controller
    public static class bad_case_8 {
        @GetMapping("/fetch")
        public void fetchAndProcess(HttpServletRequest request, HttpServletResponse response) {
            try {
                String url = request.getParameter("url");
                OkHttpClient client = new OkHttpClient();
                Request okRequest = new Request.Builder().url(url).build();
                try (Response okResponse = client.newCall(okRequest).execute()) {
                    String jsonData = okResponse.body().string();
                    ObjectMapper mapper = new ObjectMapper();
                    // ruleid: java-jacksonunsafedeserialization
                    mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
                    Object result = mapper.readValue(jsonData, Object.class);
                    response.getWriter().write("Processed data from URL");
                }
            } catch (Exception e) {
                try {
                    response.sendError(500, "Error: " + e.getMessage());
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        }
    }

    public static void bad_case_9() {
        try {
            ServerBuilder sb = Server.builder();
            sb.http(8080);
            sb.service("/api/data", (ctx, req) -> {
                return req.aggregate().thenApply(aggregated -> {
                    try {
                        String json = aggregated.content().toStringUtf8();
                        ObjectMapper mapper = new ObjectMapper();
                        // ruleid: java-jacksonunsafedeserialization
                        mapper.enableDefaultTyping();
                        Object data = mapper.readValue(json, Object.class);
                        return HttpResponse.of("Processed successfully");
                    } catch (Exception e) {
                        return HttpResponse.of(400, "application/json", "{\"error\":\"" + e.getMessage() + "\"}");
                    }
                });
            });
            Server server = sb.build();
            server.start().join();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_10() {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://api.example.com/data");
        
        try {
            org.apache.http.HttpResponse response = httpClient.execute(request);
            org.apache.http.HttpEntity entity = response.getEntity();
            if (entity != null) {
                String jsonData = org.apache.http.util.EntityUtils.toString(entity);
                ObjectMapper mapper = new ObjectMapper();
                // ruleid: java-jacksonunsafedeserialization
                mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE);
                Object result = mapper.readValue(jsonData, Object.class);
                System.out.println("Processed data from API");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_11() {
        JerseyClient client = JerseyClientBuilder.createClient();
        String jsonData = client.target("https://api.example.com/data")
                              .request()
                              .get(String.class);
        
        try {
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jacksonunsafedeserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.WRAPPER_ARRAY);
            Object result = mapper.readValue(jsonData, Object.class);
            System.out.println("Processed data with Jersey client");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_12() {
        WebClient client = WebClient.create("https://api.example.com");
        String jsonData = client.path("/data").get(String.class);
        
        try {
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jacksonunsafedeserialization
            mapper.enableDefaultTyping();
            Map<String, Object> result = mapper.readValue(jsonData, Map.class);
            System.out.println("Processed data with CXF WebClient");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_13() {
        ResteasyClient client = new ResteasyClientBuilder().build();
        String jsonData = client.target("https://api.example.com/data")
                              .request()
                              .get(String.class);
        
        try {
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jacksonunsafedeserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.JAVA_LANG_OBJECT);
            List<Object> result = mapper.readValue(jsonData, List.class);
            System.out.println("Processed data with RESTEasy client");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_14() {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(JacksonConverterFactory.create())
            .build();
        
        // Assume we have an API interface and we're handling the response
        try {
            String jsonResponse = "{\"data\": [1, 2, 3]}"; // Simulating response
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jacksonunsafedeserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
            Object result = mapper.readValue(jsonResponse, Object.class);
            System.out.println("Processed data with Retrofit");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_15() {
        try {
            // Simulating Feign client response handling
            String jsonResponse = "{\"data\": {\"items\": [1, 2, 3]}}"; // Simulating response
            
            ObjectMapper mapper = new ObjectMapper();
            // ruleid: java-jacksonunsafedeserialization
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE);
            Map<String, Object> result = mapper.readValue(jsonResponse, Map.class);
            System.out.println("Processed data with Feign client");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public static void good_case_1(HttpServletRequest request) {
        try {
            String jsonData = request.getParameter("data");
            ObjectMapper mapper = new ObjectMapper();
            // ok: java-jacksonunsafedeserialization
            mapper.activateDefaultTyping(
                BasicPolymorphicTypeValidator.builder()
                    .allowIfBaseType(MyClass.class)
                    .build()
            );
            MyClass obj = mapper.readValue(jsonData, MyClass.class);
            System.out.println("Deserialized object: " + obj);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @RestController
    public static class good_case_2 {
        @PostMapping("/process")
        public ResponseEntity<String> processData(@RequestBody String requestBody) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                // ok: java-jacksonunsafedeserialization
                mapper.activateDefaultTyping(
                    BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(Map.class)
                        .build(),
                    ObjectMapper.DefaultTyping.NON_FINAL
                );
                Map<String, Object> data = mapper.readValue(requestBody, Map.class);
                return ResponseEntity.ok("Processed: " + data.size() + " items");
            } catch (Exception e) {
                return ResponseEntity.badRequest().body("Error: " + e.getMessage());
            }
        }
    }

    public static void good_case_3() {
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        router.route().handler(BodyHandler.create());
        router.post("/api/data").handler(ctx -> {
            String body = ctx.getBodyAsString();
            try {
                ObjectMapper mapper = new ObjectMapper();
                // ok: java-jacksonunsafedeserialization
                // Using specific class instead of polymorphic deserialization
                mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
                SafeDataClass result = mapper.readValue(body, SafeDataClass.class);
                ctx.response().end("Processed data successfully");
            } catch (Exception e) {
                ctx.response().setStatusCode(400).end("Error processing data");
            }
        });
        
        vertx.createHttpServer().requestHandler(router).listen(8080);
    }

    public static void good_case_4() {
        Javalin app = Javalin.create().start(7000);
        app.post("/api/process", ctx -> {
            String requestBody = ctx.body();
            try {
                ObjectMapper mapper = new ObjectMapper();
                // ok: java-jacksonunsafedeserialization
                PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                    .allowIfSubType("com.myapp.model")
                    .build();
                mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
                List<SafeDataClass> items = mapper.readValue(requestBody, 
                    mapper.getTypeFactory().constructCollectionType(List.class, SafeDataClass.class));
                ctx.result("Processed " + items.size() + " items");
            } catch (Exception e) {
                ctx.status(400).result("Error: " + e.getMessage());
            }
        });
    }

    public static void good_case_5() {
        try {
            RatpackServer.start(server -> server
                .handlers(chain -> chain
                    .post("api/data", ctx -> {
                        ctx.getRequest().getBody().then(body -> {
                            String data = body.getText();
                            try {
                                ObjectMapper mapper = new ObjectMapper();
                                // ok: java-jacksonunsafedeserialization
                                // Using specific class without polymorphic type handling
                                SafeDataClass result = mapper.readValue(data, SafeDataClass.class);
                                ctx.render("Processed successfully");
                            } catch (Exception e) {
                                ctx.render("Error: " + e.getMessage());
                            }
                        });
                    })
                )
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @RouteBase(path = "/api")
    public static class good_case_6 {
        @Route(path = "process", methods = io.vertx.core.http.HttpMethod.POST)
        void processData(io.vertx.ext.web.RoutingContext ctx) {
            String body = ctx.getBodyAsString();
            try {
                ObjectMapper mapper = new ObjectMapper();
                // ok: java-jacksonunsafedeserialization
                // Disabling all polymorphic type handling
                mapper.deactivateDefaultTyping();
                Map<String, Object> data = mapper.readValue(body, Map.class);
                ctx.response().end("Processed data with " + data.size() + " entries");
            } catch (Exception e) {
                ctx.response().setStatusCode(400).end("Error: " + e.getMessage());
            }
        }
    }

    public static void good_case_7() {
        Spark.post("/api/data", (Request request, Response response) -> {
            String body = request.body();
            try {
                ObjectMapper mapper = new ObjectMapper();
                // ok: java-jacksonunsafedeserialization
                // Using a specific class with no polymorphic handling
                mapper.disable(DeserializationFeature.AC_REDACTED_TWILIO_ID_EMPTY_STRING_AS_NULL_OBJECT);
                SafeDataClass data = mapper.readValue(body, SafeDataClass.class);
                return "Data processed successfully";
            } catch (Exception e) {
                response.status(400);
                return "Error: " + e.getMessage();
            }
        });
    }

    @Controller
    public static class good_case_8 {
        @GetMapping("/fetch")
        public void fetchAndProcess(HttpServletRequest request, HttpServletResponse response) {
            try {
                String url = request.getParameter("url");
                OkHttpClient client = new OkHttpClient();
                Request okRequest = new Request.Builder().url(url).build();
                try (Response okResponse = client.newCall(okRequest).execute()) {
                    String jsonData = okResponse.body().string();
                    ObjectMapper mapper = new ObjectMapper();
                    // ok: java-jacksonunsafedeserialization
                    PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType("com.myapp.model")
                        .allowIfSubType("java.util.ArrayList")
                        .build();
                    mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
                    SafeDataClass result = mapper.readValue(jsonData, SafeDataClass.class);
                    response.getWriter().write("Processed data from URL");
                }
            } catch (Exception e) {
                try {
                    response.sendError(500, "Error: " + e.getMessage());
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        }
    }

    public static void good_case_9() {
        try {
            ServerBuilder sb = Server.builder();
            sb.http(8080);
            sb.service("/api/data", (ctx, req) -> {
                return req.aggregate().thenApply(aggregated -> {
                    try {
                        String json = aggregated.content().toStringUtf8();
                        ObjectMapper mapper = new ObjectMapper();
                        // ok: java-jacksonunsafedeserialization
                        // Using specific class without polymorphic type handling
                        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
                        SafeDataClass data = mapper.readValue(json, SafeDataClass.class);
                        return HttpResponse.of("Processed successfully");
                    } catch (Exception e) {
                        return HttpResponse.of(400, "application/json", "{\"error\":\"" + e.getMessage() + "\"}");
                    }
                });
            });
            Server server = sb.build();
            server.start().join();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_10() {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet("https://api.example.com/data");
        
        try {
            org.apache.http.HttpResponse response = httpClient.execute(request);
            org.apache.http.HttpEntity entity = response.getEntity();
            if (entity != null) {
                String jsonData = org.apache.http.util.EntityUtils.toString(entity);
                ObjectMapper mapper = new ObjectMapper();
                // ok: java-jacksonunsafedeserialization
                PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                    .allowIfBaseType(SafeDataClass.class)
                    .build();
                mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
                SafeDataClass result = mapper.readValue(jsonData, SafeDataClass.class);
                System.out.println("Processed data from API");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_11() {
        JerseyClient client = JerseyClientBuilder.createClient();
        String jsonData = client.target("https://api.example.com/data")
                              .request()
                              .get(String.class);
        
        try {
            ObjectMapper mapper = new ObjectMapper();
            // ok: java-jacksonunsafedeserialization
            // Using specific class without polymorphic type handling
            SafeDataClass result = mapper.readValue(jsonData, SafeDataClass.class);
            System.out.println("Processed data with Jersey client");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_12() {
        WebClient client = WebClient.create("https://api.example.com");
        String jsonData = client.path("/data").get(String.class);
        
        try {
            ObjectMapper mapper = new ObjectMapper();
            // ok: java-jacksonunsafedeserialization
            // Using a custom deserializer for specific classes
            mapper.registerModule(new SafeDeserializerModule());
            Map<String, Object> result = mapper.readValue(jsonData, Map.class);
            System.out.println("Processed data with CXF WebClient");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_13() {
        ResteasyClient client = new ResteasyClientBuilder().build();
        String jsonData = client.target("https://api.example.com/data")
                              .request()
                              .get(String.class);
        
        try {
            ObjectMapper mapper = new ObjectMapper();
            // ok: java-jacksonunsafedeserialization
            // Using a strict validator for polymorphic types
            PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfSubType("com.myapp.model")
                .denyForExactBaseType(Object.class)
                .build();
            mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
            List<SafeDataClass> result = mapper.readValue(jsonData, 
                mapper.getTypeFactory().constructCollectionType(List.class, SafeDataClass.class));
            System.out.println("Processed data with RESTEasy client");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_14() {
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(JacksonConverterFactory.create())
            .build();
        
        // Assume we have an API interface and we're handling the response
        try {
            String jsonResponse = "{\"data\": [1, 2, 3]}"; // Simulating response
            ObjectMapper mapper = new ObjectMapper();
            // ok: java-jacksonunsafedeserialization
            // Using specific types without polymorphic handling
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
            mapper.configure(DeserializationFeature.FAIL_ON_INVALID_SUBTYPE, true);
            SafeDataClass result = mapper.readValue(jsonResponse, SafeDataClass.class);
            System.out.println("Processed data with Retrofit");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_15() {
        try {
            // Simulating Feign client response handling
            String jsonResponse = "{\"data\": {\"items\": [1, 2, 3]}}"; // Simulating response
            
            ObjectMapper mapper = new ObjectMapper();
            // ok: java-jacksonunsafedeserialization
            // Using Jackson's newer, safer API for polymorphic type handling
            PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfSubType("com.myapp.model")
                .allowIfSubType("java.util")
                .build();
            mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
            Map<String, Object> result = mapper.readValue(jsonResponse, Map.class);
            System.out.println("Processed data with Feign client");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper classes
    static class MyClass {
        private String name;
        private int value;
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public int getValue() { return value; }
        public void setValue(int value) { this.value = value; }
    }
    
    static class SafeDataClass {
        private String name;
        private int value;
        private List<String> items;
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public int getValue() { return value; }
        public void setValue(int value) { this.value = value; }
        public List<String> getItems() { return items; }
        public void setItems(List<String> items) { this.items = items; }
    }
    
    static class SafeDeserializerModule extends com.fasterxml.jackson.databind.module.SimpleModule {
        public SafeDeserializerModule() {
            // Add custom deserializers here
        }
    }
}
// {/fact}