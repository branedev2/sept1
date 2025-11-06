import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.representer.Representer;
import org.yaml.snakeyaml.resolver.Resolver;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;

import spark.Request;
import spark.Response;

import ratpack.handling.Context;
import ratpack.http.Request;

import io.javalin.http.Context;

import org.jboss.resteasy.spi.HttpRequest;

import javax.ws.rs.core.Request;

import com.google.api.client.http.HttpRequest;

import okhttp3.Request;

import java.io.InputStream;
import java.io.StringReader;
import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.io.BufferedReader;

// Security Issue: Unsafe YAML Deserialization (CWE-502)
// This file demonstrates vulnerable and secure ways to use SnakeYAML library

// True Positive Examples (Vulnerable/Insecure Code)

public class UnsafeYamlDeserializationExamples {

    // Spring Web MVC example
    @RestController
    public static class BadCase1 {
        @PostMapping("/process-yaml")
        public ResponseEntity<String> processYaml(@RequestBody String yamlContent) {
            try {
                // ruleid: java-unsafe-yaml-deserialization
                Yaml yaml = new Yaml();
                Map<String, Object> data = yaml.load(yamlContent);
                return ResponseEntity.ok("Processed YAML: " + data.toString());
            } catch (Exception e) {
                return ResponseEntity.badRequest().body("Error processing YAML: " + e.getMessage());
            }
        }
    }

    // Servlet API example
    public static class BadCase2 implements javax.servlet.http.HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
            BufferedReader reader = request.getReader();
            StringBuilder yamlContent = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                yamlContent.append(line);
            }
            
            // ruleid: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml(new Constructor());
            Map<String, Object> data = yaml.load(yamlContent.toString());
            
            response.getWriter().write("Processed YAML: " + data.toString());
        }
    }

    // Sun HTTP Server example
    public static class BadCase3 implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStream inputStream = exchange.getRequestBody();
                byte[] requestBytes = inputStream.readAllBytes();
                String yamlContent = new String(requestBytes);
                
                // ruleid: java-unsafe-yaml-deserialization
                Yaml yaml = new Yaml(new Constructor(), new Representer());
                Object parsedYaml = yaml.load(yamlContent);
                
                String response = "Processed YAML: " + parsedYaml.toString();
                exchange.sendResponseHeaders(200, response.length());
                exchange.getResponseBody().write(response.getBytes());
                exchange.getResponseBody().close();
            }
        }
    }

    // Vert.x example
    public static class BadCase4 {
        public void setupRouter(Vertx vertx) {
            Router router = Router.router(vertx);
            
            router.post("/yaml").handler(routingContext -> {
                routingContext.request().bodyHandler(buffer -> {
                    String yamlContent = buffer.toString();
                    
                    // ruleid: java-unsafe-yaml-deserialization
                    Yaml yaml = new Yaml(new Constructor(), new Representer(), new DumperOptions());
                    Map<String, Object> data = yaml.load(yamlContent);
                    
                    routingContext.response()
                        .putHeader("content-type", "text/plain")
                        .end("Processed YAML: " + data.toString());
                });
            });
            
            vertx.createHttpServer().requestHandler(router).listen(8080);
        }
    }

    // Undertow example
    public static class BadCase5 {
        public void handleRequest(HttpServerExchange exchange) {
            exchange.getRequestReceiver().receiveFullString((exchange1, yamlContent) -> {
                // ruleid: java-unsafe-yaml-deserialization
                Yaml yaml = new Yaml(new Constructor(), new Representer(), new DumperOptions(), new LoaderOptions());
                Map<String, Object> data = yaml.load(yamlContent);
                
                exchange1.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
                exchange1.getResponseSender().send("Processed YAML: " + data.toString());
            });
        }
    }

    // Spark framework example
    public static class BadCase6 {
        public void setupRoutes() {
            spark.Spark.post("/yaml", (spark.Request request, spark.Response response) -> {
                String yamlContent = request.body();
                
                // ruleid: java-unsafe-yaml-deserialization
                Yaml yaml = new Yaml();
                yaml.setName("ConfigParser");
                Map<String, Object> data = yaml.load(yamlContent);
                
                return "Processed YAML: " + data.toString();
            });
        }
    }

    // Ratpack example
    public static class BadCase7 {
        public void handleYaml(ratpack.handling.Context ctx) {
            ctx.getRequest().getBody().then(body -> {
                String yamlContent = body.getText();
                
                // ruleid: java-unsafe-yaml-deserialization
                Yaml yaml = new Yaml(new Resolver());
                Map<String, Object> data = yaml.load(yamlContent);
                
                ctx.getResponse().send("Processed YAML: " + data.toString());
            });
        }
    }

    // Javalin example
    public static class BadCase8 {
        public void setupRoutes() {
            io.javalin.Javalin app = io.javalin.Javalin.create();
            app.post("/yaml", ctx -> {
                String yamlContent = ctx.body();
                
                // ruleid: java-unsafe-yaml-deserialization
                Yaml yaml = new Yaml(new Constructor(), new Representer(), new DumperOptions(), new LoaderOptions(), new Resolver());
                Map<String, Object> data = yaml.load(yamlContent);
                
                ctx.result("Processed YAML: " + data.toString());
            });
        }
    }

    // RESTEasy example
    public static class BadCase9 {
        @javax.ws.rs.POST
        @javax.ws.rs.Path("/yaml")
        @javax.ws.rs.Consumes("text/plain")
        public String processYaml(String yamlContent) {
            // ruleid: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml(new Constructor());
            Map<String, Object> data = yaml.load(yamlContent);
            
            return "Processed YAML: " + data.toString();
        }
    }

    // JAX-RS example
    public static class BadCase10 {
        @javax.ws.rs.POST
        @javax.ws.rs.Path("/yaml")
        @javax.ws.rs.Consumes("text/plain")
        public javax.ws.rs.core.Response processYaml(String yamlContent) {
            // ruleid: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(new StringReader(yamlContent));
            
            return javax.ws.rs.core.Response.ok("Processed YAML: " + data.toString()).build();
        }
    }

    // Google HTTP Client example
    public static class BadCase11 {
        public String processGoogleHttpRequest(com.google.api.client.http.HttpRequest request) throws IOException {
            String yamlContent = request.getContent().toString();
            
            // ruleid: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.loadAs(yamlContent, Map.class);
            
            return "Processed YAML: " + data.toString();
        }
    }

    // OkHttp example
    public static class BadCase12 {
        public String processOkHttpRequest(okhttp3.Request request) throws IOException {
            String yamlContent = request.body().toString();
            
            // ruleid: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml();
            Map<String, Object> data = (Map<String, Object>) yaml.load(yamlContent);
            
            return "Processed YAML: " + data.toString();
        }
    }

    // Spring WebFlux example
    public static class BadCase13 {
        @org.springframework.web.bind.annotation.PostMapping("/reactive-yaml")
        public reactor.core.publisher.Mono<String> processReactiveYaml(@org.springframework.web.bind.annotation.RequestBody String yamlContent) {
            // ruleid: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(yamlContent);
            
            return reactor.core.publisher.Mono.just("Processed YAML: " + data.toString());
        }
    }

    // Apache HttpComponents example
    public static class BadCase14 {
        public String processApacheHttpRequest(org.apache.http.HttpRequest request) throws IOException {
            org.apache.http.HttpEntityEnclosingRequest entityRequest = (org.apache.http.HttpEntityEnclosingRequest) request;
            org.apache.http.HttpEntity entity = entityRequest.getEntity();
            
            java.io.InputStream inputStream = entity.getContent();
            java.util.Scanner scanner = new java.util.Scanner(inputStream).useDelimiter("\\A");
            String yamlContent = scanner.hasNext() ? scanner.next() : "";
            
            // ruleid: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(yamlContent);
            
            return "Processed YAML: " + data.toString();
        }
    }

    // Play Framework example
    public static class BadCase15 {
        public play.mvc.Result processPlayRequest(play.mvc.Http.Request request) {
            String yamlContent = request.body().asText();
            
            // ruleid: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(yamlContent);
            
            return play.mvc.Results.ok("Processed YAML: " + data.toString());
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Spring Web MVC example with SafeConstructor
    @RestController
    public static class GoodCase1 {
        @PostMapping("/process-yaml-safely")
        public ResponseEntity<String> processYamlSafely(@RequestBody String yamlContent) {
            try {
                // ok: java-unsafe-yaml-deserialization
                Yaml yaml = new Yaml(new SafeConstructor());
                Map<String, Object> data = yaml.load(yamlContent);
                return ResponseEntity.ok("Processed YAML safely: " + data.toString());
            } catch (Exception e) {
                return ResponseEntity.badRequest().body("Error processing YAML: " + e.getMessage());
            }
        }
    }

    // Servlet API example with SafeConstructor
    public static class GoodCase2 implements javax.servlet.http.HttpServlet {
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
            BufferedReader reader = request.getReader();
            StringBuilder yamlContent = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                yamlContent.append(line);
            }
            
            // ok: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml(new SafeConstructor());
            Map<String, Object> data = yaml.load(yamlContent.toString());
            
            response.getWriter().write("Processed YAML safely: " + data.toString());
        }
    }

    // Sun HTTP Server example with SafeConstructor
    public static class GoodCase3 implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStream inputStream = exchange.getRequestBody();
                byte[] requestBytes = inputStream.readAllBytes();
                String yamlContent = new String(requestBytes);
                
                // ok: java-unsafe-yaml-deserialization
                Yaml yaml = new Yaml(new SafeConstructor(), new Representer());
                Object parsedYaml = yaml.load(yamlContent);
                
                String response = "Processed YAML safely: " + parsedYaml.toString();
                exchange.sendResponseHeaders(200, response.length());
                exchange.getResponseBody().write(response.getBytes());
                exchange.getResponseBody().close();
            }
        }
    }

    // Vert.x example with SafeConstructor
    public static class GoodCase4 {
        public void setupRouter(Vertx vertx) {
            Router router = Router.router(vertx);
            
            router.post("/yaml").handler(routingContext -> {
                routingContext.request().bodyHandler(buffer -> {
                    String yamlContent = buffer.toString();
                    
                    // ok: java-unsafe-yaml-deserialization
                    Yaml yaml = new Yaml(new SafeConstructor(), new Representer(), new DumperOptions());
                    Map<String, Object> data = yaml.load(yamlContent);
                    
                    routingContext.response()
                        .putHeader("content-type", "text/plain")
                        .end("Processed YAML safely: " + data.toString());
                });
            });
            
            vertx.createHttpServer().requestHandler(router).listen(8080);
        }
    }

    // Undertow example with SafeConstructor
    public static class GoodCase5 {
        public void handleRequest(HttpServerExchange exchange) {
            exchange.getRequestReceiver().receiveFullString((exchange1, yamlContent) -> {
                // ok: java-unsafe-yaml-deserialization
                Yaml yaml = new Yaml(new SafeConstructor(), new Representer(), new DumperOptions(), new LoaderOptions());
                Map<String, Object> data = yaml.load(yamlContent);
                
                exchange1.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
                exchange1.getResponseSender().send("Processed YAML safely: " + data.toString());
            });
        }
    }

    // Spark framework example with SafeConstructor
    public static class GoodCase6 {
        public void setupRoutes() {
            spark.Spark.post("/yaml", (spark.Request request, spark.Response response) -> {
                String yamlContent = request.body();
                
                // ok: java-unsafe-yaml-deserialization
                Yaml yaml = new Yaml(new SafeConstructor());
                Map<String, Object> data = yaml.load(yamlContent);
                
                return "Processed YAML safely: " + data.toString();
            });
        }
    }

    // Ratpack example with SafeConstructor
    public static class GoodCase7 {
        public void handleYaml(ratpack.handling.Context ctx) {
            ctx.getRequest().getBody().then(body -> {
                String yamlContent = body.getText();
                
                // ok: java-unsafe-yaml-deserialization
                Yaml yaml = new Yaml(new SafeConstructor(), new Representer(), new DumperOptions());
                Map<String, Object> data = yaml.load(yamlContent);
                
                ctx.getResponse().send("Processed YAML safely: " + data.toString());
            });
        }
    }

    // Javalin example with SafeConstructor
    public static class GoodCase8 {
        public void setupRoutes() {
            io.javalin.Javalin app = io.javalin.Javalin.create();
            app.post("/yaml", ctx -> {
                String yamlContent = ctx.body();
                
                // ok: java-unsafe-yaml-deserialization
                Yaml yaml = new Yaml(new SafeConstructor(), new Representer(), new DumperOptions(), new LoaderOptions(), new Resolver());
                Map<String, Object> data = yaml.load(yamlContent);
                
                ctx.result("Processed YAML safely: " + data.toString());
            });
        }
    }

    // RESTEasy example with SafeConstructor
    public static class GoodCase9 {
        @javax.ws.rs.POST
        @javax.ws.rs.Path("/yaml")
        @javax.ws.rs.Consumes("text/plain")
        public String processYaml(String yamlContent) {
            // ok: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml(new SafeConstructor());
            Map<String, Object> data = yaml.load(yamlContent);
            
            return "Processed YAML safely: " + data.toString();
        }
    }

    // JAX-RS example with SafeConstructor
    public static class GoodCase10 {
        @javax.ws.rs.POST
        @javax.ws.rs.Path("/yaml")
        @javax.ws.rs.Consumes("text/plain")
        public javax.ws.rs.core.Response processYaml(String yamlContent) {
            // ok: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml(new SafeConstructor());
            Map<String, Object> data = yaml.load(new StringReader(yamlContent));
            
            return javax.ws.rs.core.Response.ok("Processed YAML safely: " + data.toString()).build();
        }
    }

    // Google HTTP Client example with SafeConstructor
    public static class GoodCase11 {
        public String processGoogleHttpRequest(com.google.api.client.http.HttpRequest request) throws IOException {
            String yamlContent = request.getContent().toString();
            
            // ok: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml(new SafeConstructor());
            Map<String, Object> data = yaml.loadAs(yamlContent, Map.class);
            
            return "Processed YAML safely: " + data.toString();
        }
    }

    // OkHttp example with SafeConstructor
    public static class GoodCase12 {
        public String processOkHttpRequest(okhttp3.Request request) throws IOException {
            String yamlContent = request.body().toString();
            
            // ok: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml(new SafeConstructor());
            Map<String, Object> data = (Map<String, Object>) yaml.load(yamlContent);
            
            return "Processed YAML safely: " + data.toString();
        }
    }

    // Spring WebFlux example with SafeConstructor
    public static class GoodCase13 {
        @org.springframework.web.bind.annotation.PostMapping("/reactive-yaml")
        public reactor.core.publisher.Mono<String> processReactiveYaml(@org.springframework.web.bind.annotation.RequestBody String yamlContent) {
            // ok: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml(new SafeConstructor());
            Map<String, Object> data = yaml.load(yamlContent);
            
            return reactor.core.publisher.Mono.just("Processed YAML safely: " + data.toString());
        }
    }

    // Apache HttpComponents example with SafeConstructor
    public static class GoodCase14 {
        public String processApacheHttpRequest(org.apache.http.HttpRequest request) throws IOException {
            org.apache.http.HttpEntityEnclosingRequest entityRequest = (org.apache.http.HttpEntityEnclosingRequest) request;
            org.apache.http.HttpEntity entity = entityRequest.getEntity();
            
            java.io.InputStream inputStream = entity.getContent();
            java.util.Scanner scanner = new java.util.Scanner(inputStream).useDelimiter("\\A");
            String yamlContent = scanner.hasNext() ? scanner.next() : "";
            
            // ok: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml(new SafeConstructor());
            Map<String, Object> data = yaml.load(yamlContent);
            
            return "Processed YAML safely: " + data.toString();
        }
    }

    // Play Framework example with SafeConstructor
    public static class GoodCase15 {
        public play.mvc.Result processPlayRequest(play.mvc.Http.Request request) {
            String yamlContent = request.body().asText();
            
            // ok: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml(new SafeConstructor());
            Map<String, Object> data = yaml.load(yamlContent);
            
            return play.mvc.Results.ok("Processed YAML safely: " + data.toString());
        }
    }
}