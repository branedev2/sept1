import java.util.concurrent.*;
import java.util.Map;
import java.util.HashMap;
import java.util.function.Supplier;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;
import java.lang.reflect.Field;

// Spring Framework imports
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;

// Micronaut imports
import io.micronaut.http.annotation.*;
import io.micronaut.http.*;

// Quarkus imports
import javax.ws.rs.*;
import javax.ws.rs.core.Response;

// Vert.x imports
import io.vertx.core.*;
import io.vertx.ext.web.*;
import io.vertx.ext.web.handler.*;

// Play Framework imports
import play.mvc.*;

// Spark Framework imports
import spark.Request;
import spark.Response;
import static spark.Spark.*;

// Dropwizard imports
import io.dropwizard.Application;
import io.dropwizard.setup.Environment;

// Javalin imports
import io.javalin.Javalin;
import io.javalin.http.Context;

// Ratpack imports
import ratpack.server.RatpackServer;
import ratpack.handling.Context;

// Helidon imports
import io.helidon.webserver.*;

// Ktor imports
import io.ktor.application.*;
import io.ktor.response.*;
import io.ktor.request.*;
import io.ktor.routing.*;
import io.ktor.server.engine.*;
import io.ktor.server.netty.*;

// Akka HTTP imports
import akka.actor.ActorSystem;
import akka.http.javadsl.Http;
import akka.http.javadsl.model.*;
import akka.http.javadsl.server.*;

// Security Issue: Using InheritableThreadLocal can lead to security vulnerabilities as it allows values to be inherited by child threads,
// potentially exposing sensitive information across thread boundaries. This can lead to race conditions (CWE-362) and information leakage.

// True Positive Examples (Vulnerable/Insecure Code)

public class InheritableThreadLocalExamples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    public static void bad_case_1() {
        // Spring Framework - Using InheritableThreadLocal to store user session data
        @RestController
        class UserController {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<String> userSession = new InheritableThreadLocal<>();
            
            @GetMapping("/user")
            public ResponseEntity<String> getUser(@RequestHeader("Authorization") String authHeader) {
                userSession.set(authHeader);
                
                // Spawn a new thread that inherits the sensitive auth data
                new Thread(() -> {
                    String inheritedAuth = userSession.get();
                    System.out.println("Using auth in child thread: " + inheritedAuth);
                }).start();
                
                return ResponseEntity.ok("User processed");
            }
        }
    }
    
    public static void bad_case_2() {
        // Micronaut Framework - Using InheritableThreadLocal for API key storage
        @Controller("/api")
        class ApiKeyController {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<String> apiKeyStorage = new InheritableThreadLocal<>();
            
            @Post("/process")
            public HttpResponse<String> processRequest(HttpRequest<?> request) {
                String apiKey = request.getHeaders().get("X-API-Key");
                apiKeyStorage.set(apiKey);
                
                CompletableFuture.runAsync(() -> {
                    // Child thread inherits the API key
                    String key = apiKeyStorage.get();
                    System.out.println("Processing with key: " + key);
                });
                
                return HttpResponse.ok("Request processed");
            }
        }
    }
    
    public static void bad_case_3() {
        // Quarkus - Using InheritableThreadLocal for storing database credentials
        @Path("/database")
        class DatabaseResource {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<Map<String, String>> dbCredentials = 
                new InheritableThreadLocal<Map<String, String>>() {
                    @Override
                    protected Map<String, String> initialValue() {
                        return new HashMap<>();
                    }
                };
            
            @POST
            @Path("/connect")
            public Response connect(@HeaderParam("DB-User") String user, @HeaderParam("DB-Password") String password) {
                Map<String, String> creds = dbCredentials.get();
                creds.put("user", user);
                creds.put("password", password);
                
                ExecutorService executor = Executors.newSingleThreadExecutor();
                executor.submit(() -> {
                    // Child thread inherits the credentials
                    Map<String, String> inheritedCreds = dbCredentials.get();
                    System.out.println("Connecting with: " + inheritedCreds.get("user"));
                });
                
                return Response.ok("Database connection initiated").build();
            }
        }
    }
    
    public static void bad_case_4() {
        // Vert.x - Using InheritableThreadLocal for request context
        class VertxServer {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<JsonObject> requestContext = new InheritableThreadLocal<>();
            
            public void setupRouter(Router router) {
                router.post("/process").handler(ctx -> {
                    JsonObject requestData = ctx.getBodyAsJson();
                    requestContext.set(requestData);
                    
                    // Using a worker thread that inherits the context
                    Vertx.currentContext().owner().executeBlocking(promise -> {
                        JsonObject inheritedData = requestContext.get();
                        System.out.println("Processing: " + inheritedData.encode());
                        promise.complete();
                    }, result -> {
                        ctx.response().end("Processed");
                    });
                });
            }
        }
    }
    
    public static void bad_case_5() {
        // Play Framework - Using InheritableThreadLocal for user identity
        class UserAction extends Controller {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<String> userIdentity = new InheritableThreadLocal<>();
            
            public Result authenticate(Http.Request request) {
                String userId = request.header("User-Id").orElse("");
                userIdentity.set(userId);
                
                // Using Play's async execution which creates new threads
                return CompletableFuture.supplyAsync(() -> {
                    // Child thread inherits the user identity
                    String id = userIdentity.get();
                    return ok("Authenticated user: " + id);
                }).thenApply(Result::async).toCompletableFuture().join();
            }
        }
    }
    
    public static void bad_case_6() {
        // Spark Framework - Using InheritableThreadLocal for session tokens
        class SparkApp {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<String> sessionToken = new InheritableThreadLocal<>();
            
            public void setupRoutes() {
                post("/login", (Request req, Response res) -> {
                    String token = req.headers("Session-Token");
                    sessionToken.set(token);
                    
                    // Background task in a new thread
                    new Thread(() -> {
                        String inheritedToken = sessionToken.get();
                        System.out.println("Using session: " + inheritedToken);
                    }).start();
                    
                    return "Logged in";
                });
            }
        }
    }
    
    public static void bad_case_7() {
        // Dropwizard - Using InheritableThreadLocal for tenant information
        class MultiTenantResource {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<String> tenantId = new InheritableThreadLocal<>();
            
            @POST
            @Path("/tenant/action")
            public String performTenantAction(@HeaderParam("X-Tenant-ID") String tenant) {
                tenantId.set(tenant);
                
                // Using Dropwizard's managed executor service
                ExecutorService executor = Executors.newSingleThreadExecutor();
                executor.submit(() -> {
                    // Child thread inherits the tenant ID
                    String id = tenantId.get();
                    System.out.println("Processing for tenant: " + id);
                });
                
                return "Action scheduled";
            }
        }
    }
    
    public static void bad_case_8() {
        // Javalin - Using InheritableThreadLocal for authentication context
        class JavalinApp {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<Map<String, Object>> authContext = 
                new InheritableThreadLocal<Map<String, Object>>() {
                    @Override
                    protected Map<String, Object> initialValue() {
                        return new HashMap<>();
                    }
                };
            
            public void configureRoutes(Javalin app) {
                app.post("/secure", ctx -> {
                    String authToken = ctx.header("Authorization");
                    Map<String, Object> context = authContext.get();
                    context.put("token", authToken);
                    
                    CompletableFuture.runAsync(() -> {
                        // Child thread inherits the auth context
                        Map<String, Object> inherited = authContext.get();
                        System.out.println("Token: " + inherited.get("token"));
                    });
                    
                    ctx.result("Processed");
                });
            }
        }
    }
    
    public static void bad_case_9() {
        // Ratpack - Using InheritableThreadLocal for request tracking
        class RatpackApp {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<String> requestId = new InheritableThreadLocal<>();
            
            public void startServer() throws Exception {
                RatpackServer.start(server -> server
                    .handlers(chain -> chain
                        .post("track", ctx -> {
                            String id = ctx.getRequest().getHeaders().get("X-Request-ID");
                            requestId.set(id);
                            
                            // Using Ratpack's execution model which may use different threads
                            ctx.exec().fork()
                                .start(execution -> {
                                    // Child execution inherits the request ID
                                    String trackingId = requestId.get();
                                    System.out.println("Tracking request: " + trackingId);
                                    ctx.render("Request tracked");
                                });
                        })
                    )
                );
            }
        }
    }
    
    public static void bad_case_10() {
        // Helidon - Using InheritableThreadLocal for security context
        class HelidonService implements Service {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<String> securityContext = new InheritableThreadLocal<>();
            
            @Override
            public void update(Routing.Rules rules) {
                rules.post("/secure-operation", (req, res) -> {
                    String secToken = req.headers().value("Security-Token").orElse("");
                    securityContext.set(secToken);
                    
                    CompletableFuture.runAsync(() -> {
                        // Child thread inherits the security context
                        String token = securityContext.get();
                        System.out.println("Using security token: " + token);
                    });
                    
                    res.send("Operation scheduled");
                });
            }
        }
    }
    
    public static void bad_case_11() {
        // Ktor - Using InheritableThreadLocal for user preferences
        class KtorApp {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<Map<String, String>> userPreferences = 
                new InheritableThreadLocal<Map<String, String>>() {
                    @Override
                    protected Map<String, String> initialValue() {
                        return new HashMap<>();
                    }
                };
            
            public void configureRouting(Application application) {
                application.routing(routing -> {
                    routing.post("/preferences", request -> {
                        String theme = request.call.request.header("X-Theme");
                        String language = request.call.request.header("X-Language");
                        
                        Map<String, String> prefs = userPreferences.get();
                        prefs.put("theme", theme);
                        prefs.put("language", language);
                        
                        // Background processing
                        new Thread(() -> {
                            // Child thread inherits preferences
                            Map<String, String> inherited = userPreferences.get();
                            System.out.println("Theme: " + inherited.get("theme"));
                        }).start();
                        
                        request.call.respond("Preferences saved");
                        return null;
                    });
                });
            }
        }
    }
    
    public static void bad_case_12() {
        // Akka HTTP - Using InheritableThreadLocal for request metadata
        class AkkaHttpServer {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<Map<String, String>> requestMetadata = 
                new InheritableThreadLocal<Map<String, String>>() {
                    @Override
                    protected Map<String, String> initialValue() {
                        return new HashMap<>();
                    }
                };
            
            public Route createRoute() {
                return post(() -> 
                    path("process", () -> 
                        extractRequest(request -> {
                            Map<String, String> metadata = requestMetadata.get();
                            metadata.put("client-ip", request.getHeader("X-Forwarded-For").orElse("unknown"));
                            metadata.put("user-agent", request.getHeader("User-Agent").orElse("unknown"));
                            
                            // Using Akka's thread pool
                            CompletableFuture.runAsync(() -> {
                                // Child thread inherits metadata
                                Map<String, String> inherited = requestMetadata.get();
                                System.out.println("Client IP: " + inherited.get("client-ip"));
                            });
                            
                            return complete("Request processed");
                        })
                    )
                );
            }
        }
    }
    
    public static void bad_case_13() {
        // Apache Tomcat - Using InheritableThreadLocal in a servlet filter
        class SecurityFilter implements javax.servlet.Filter {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<String> userRole = new InheritableThreadLocal<>();
            
            @Override
            public void doFilter(javax.servlet.ServletRequest request, 
                                javax.servlet.ServletResponse response, 
                                javax.servlet.FilterChain chain) throws java.io.IOException, javax.servlet.ServletException {
                
                javax.servlet.http.HttpServletRequest httpRequest = (javax.servlet.http.HttpServletRequest) request;
                String role = httpRequest.getHeader("X-User-Role");
                userRole.set(role);
                
                // Async processing in Tomcat
                request.startAsync().start(() -> {
                    // Child thread inherits the role
                    String inheritedRole = userRole.get();
                    System.out.println("Processing as role: " + inheritedRole);
                });
                
                chain.doFilter(request, response);
            }
            
            // Other filter methods omitted for brevity
        }
    }
    
    public static void bad_case_14() {
        // Undertow - Using InheritableThreadLocal for request tracing
        class TracingHandler implements io.undertow.server.HttpHandler {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<String> traceId = new InheritableThreadLocal<>();
            
            @Override
            public void handleRequest(io.undertow.server.HttpServerExchange exchange) throws Exception {
                if (exchange.isInIoThread()) {
                    exchange.dispatch(this);
                    return;
                }
                
                String requestTraceId = exchange.getRequestHeaders().getFirst("X-Trace-ID");
                traceId.set(requestTraceId);
                
                // Worker thread processing
                exchange.getConnection().getWorker().execute(() -> {
                    // Child thread inherits the trace ID
                    String inheritedId = traceId.get();
                    System.out.println("Processing trace: " + inheritedId);
                });
                
                exchange.getResponseSender().send("Request traced");
            }
        }
    }
    
    public static void bad_case_15() {
        // Jetty - Using InheritableThreadLocal for transaction context
        class TransactionHandler extends org.eclipse.jetty.server.handler.AbstractHandler {
            // ruleid: java-inheritable-thread-local
            private static final InheritableThreadLocal<String> transactionId = new InheritableThreadLocal<>();
            
            @Override
            public void handle(String target, 
                              org.eclipse.jetty.server.Request baseRequest, 
                              javax.servlet.http.HttpServletRequest request, 
                              javax.servlet.http.HttpServletResponse response) throws java.io.IOException, javax.servlet.ServletException {
                
                String txId = request.getHeader("X-Transaction-ID");
                transactionId.set(txId);
                
                // Async processing in Jetty
                baseRequest.startAsync();
                new Thread(() -> {
                    try {
                        // Child thread inherits the transaction ID
                        String inheritedTxId = transactionId.get();
                        System.out.println("Processing transaction: " + inheritedTxId);
                        response.getWriter().println("Transaction processed");
                        baseRequest.getAsyncContext().complete();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();
                
                baseRequest.setHandled(true);
            }
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public static void good_case_1() {
        // Spring Framework - Using ThreadLocal instead of InheritableThreadLocal
        @RestController
        class UserController {
            // ok: java-inheritable-thread-local
            private static final ThreadLocal<String> userSession = new ThreadLocal<>();
            
            @GetMapping("/user")
            public ResponseEntity<String> getUser(@RequestHeader("Authorization") String authHeader) {
                userSession.set(authHeader);
                
                // Explicitly pass data to new thread instead of relying on inheritance
                String auth = userSession.get();
                new Thread(() -> {
                    System.out.println("Using auth in child thread: " + auth);
                }).start();
                
                return ResponseEntity.ok("User processed securely");
            }
        }
    }
    
    public static void good_case_2() {
        // Micronaut Framework - Using explicit parameter passing instead of InheritableThreadLocal
        @Controller("/api")
        class ApiKeyController {
            // ok: java-inheritable-thread-local
            private static final ThreadLocal<String> apiKeyStorage = new ThreadLocal<>();
            
            @Post("/process")
            public HttpResponse<String> processRequest(HttpRequest<?> request) {
                String apiKey = request.getHeaders().get("X-API-Key");
                apiKeyStorage.set(apiKey);
                
                // Explicitly pass the API key to the async task
                String key = apiKeyStorage.get();
                CompletableFuture.runAsync(() -> {
                    System.out.println("Processing with key: " + key);
                });
                
                return HttpResponse.ok("Request processed securely");
            }
        }
    }
    
    public static void good_case_3() {
        // Quarkus - Using context propagation instead of InheritableThreadLocal
        @Path("/database")
        class DatabaseResource {
            // ok: java-inheritable-thread-local
            private static final ThreadLocal<Map<String, String>> dbCredentials = ThreadLocal.withInitial(HashMap::new);
            
            @POST
            @Path("/connect")
            public Response connect(@HeaderParam("DB-User") String user, @HeaderParam("DB-Password") String password) {
                Map<String, String> creds = dbCredentials.get();
                creds.put("user", user);
                creds.put("password", password);
                
                // Create a copy of credentials for the new thread
                final Map<String, String> threadSafeCreds = new HashMap<>(creds);
                
                ExecutorService executor = Executors.newSingleThreadExecutor();
                executor.submit(() -> {
                    System.out.println("Connecting with: " + threadSafeCreds.get("user"));
                });
                
                return Response.ok("Database connection initiated securely").build();
            }
        }
    }
    
    public static void good_case_4() {
        // Vert.x - Using Vert.x context for data sharing instead of InheritableThreadLocal
        class VertxServer {
            public void setupRouter(Router router) {
                router.post("/process").handler(ctx -> {
                    JsonObject requestData = ctx.getBodyAsJson();
                    
                    // Using Vert.x context data which is properly scoped
                    // ok: java-inheritable-thread-local
                    ctx.put("requestData", requestData);
                    
                    // Using a worker thread with context
                    Vertx.currentContext().owner().executeBlocking(promise -> {
                        JsonObject contextData = ctx.get("requestData");
                        System.out.println("Processing: " + contextData.encode());
                        promise.complete();
                    }, result -> {
                        ctx.response().end("Processed securely");
                    });
                });
            }
        }
    }
    
    public static void good_case_5() {
        // Play Framework - Using explicit parameter passing
        class UserAction extends Controller {
            // ok: java-inheritable-thread-local
            private static final ThreadLocal<String> userIdentity = new ThreadLocal<>();
            
            public Result authenticate(Http.Request request) {
                String userId = request.header("User-Id").orElse("");
                userIdentity.set(userId);
                
                // Explicitly pass the user ID to the async task
                final String id = userId;
                return CompletableFuture.supplyAsync(() -> {
                    return ok("Authenticated user: " + id);
                }).thenApply(Result::async).toCompletableFuture().join();
            }
        }
    }
    
    public static void good_case_6() {
        // Spark Framework - Using explicit parameter passing
        class SparkApp {
            // ok: java-inheritable-thread-local
            private static final ThreadLocal<String> sessionToken = new ThreadLocal<>();
            
            public void setupRoutes() {
                post("/login", (Request req, Response res) -> {
                    String token = req.headers("Session-Token");
                    sessionToken.set(token);
                    
                    // Explicitly pass the token to the new thread
                    final String secureToken = token;
                    new Thread(() -> {
                        System.out.println("Using session: " + secureToken);
                    }).start();
                    
                    return "Logged in securely";
                });
            }
        }
    }
    
    public static void good_case_7() {
        // Dropwizard - Using explicit parameter passing
        class MultiTenantResource {
            // ok: java-inheritable-thread-local
            private static final ThreadLocal<String> tenantId = new ThreadLocal<>();
            
            @POST
            @Path("/tenant/action")
            public String performTenantAction(@HeaderParam("X-Tenant-ID") String tenant) {
                tenantId.set(tenant);
                
                // Explicitly pass the tenant ID to the executor
                final String id = tenant;
                ExecutorService executor = Executors.newSingleThreadExecutor();
                executor.submit(() -> {
                    System.out.println("Processing for tenant: " + id);
                });
                
                return "Action scheduled securely";
            }
        }
    }
    
    public static void good_case_8() {
        // Javalin - Using context attributes instead of InheritableThreadLocal
        class JavalinApp {
            public void configureRoutes(Javalin app) {
                app.post("/secure", ctx -> {
                    String authToken = ctx.header("Authorization");
                    
                    // Using a local variable instead of ThreadLocal
                    // ok: java-inheritable-thread-local
                    final String secureToken = authToken;
                    
                    CompletableFuture.runAsync(() -> {
                        System.out.println("Token: " + secureToken);
                    });
                    
                    ctx.result("Processed securely");
                });
            }
        }
    }
    
    public static void good_case_9() {
        // Ratpack - Using Promise API instead of InheritableThreadLocal
        class RatpackApp {
            public void startServer() throws Exception {
                RatpackServer.start(server -> server
                    .handlers(chain -> chain
                        .post("track", ctx -> {
                            String id = ctx.getRequest().getHeaders().get("X-Request-ID");
                            
                            // Using Ratpack's Promise API which handles thread context properly
                            // ok: java-inheritable-thread-local
                            ctx.promise(fulfiller -> {
                                System.out.println("Tracking request: " + id);
                                fulfiller.success(id);
                            }).then(trackingId -> {
                                ctx.render("Request " + trackingId + " tracked securely");
                            });
                        })
                    )
                );
            }
        }
    }
    
    public static void good_case_10() {
        // Helidon - Using request scoped context
        class HelidonService implements Service {
            @Override
            public void update(Routing.Rules rules) {
                rules.post("/secure-operation", (req, res) -> {
                    String secToken = req.headers().value("Security-Token").orElse("");
                    
                    // Using a final variable for thread safety
                    // ok: java-inheritable-thread-local
                    final String token = secToken;
                    
                    CompletableFuture.runAsync(() -> {
                        System.out.println("Using security token: " + token);
                    });
                    
                    res.send("Operation scheduled securely");
                });
            }
        }
    }
    
    public static void good_case_11() {
        // Ktor - Using explicit parameter passing
        class KtorApp {
            public void configureRouting(Application application) {
                application.routing(routing -> {
                    routing.post("/preferences", request -> {
                        String theme = request.call.request.header("X-Theme");
                        String language = request.call.request.header("X-Language");
                        
                        // Create a thread-safe copy of preferences
                        // ok: java-inheritable-thread-local
                        final Map<String, String> prefs = new HashMap<>();
                        prefs.put("theme", theme);
                        prefs.put("language", language);
                        
                        // Background processing with explicit parameter
                        new Thread(() -> {
                            System.out.println("Theme: " + prefs.get("theme"));
                        }).start();
                        
                        request.call.respond("Preferences saved securely");
                        return null;
                    });
                });
            }
        }
    }
    
    public static void good_case_12() {
        // Akka HTTP - Using immutable data structures
        class AkkaHttpServer {
            public Route createRoute() {
                return post(() -> 
                    path("process", () -> 
                        extractRequest(request -> {
                            // Create an immutable map for thread safety
                            // ok: java-inheritable-thread-local
                            final Map<String, String> metadata = Map.of(
                                "client-ip", request.getHeader("X-Forwarded-For").orElse("unknown"),
                                "user-agent", request.getHeader("User-Agent").orElse("unknown")
                            );
                            
                            // Using Akka's thread pool with explicit parameter
                            CompletableFuture.runAsync(() -> {
                                System.out.println("Client IP: " + metadata.get("client-ip"));
                            });
                            
                            return complete("Request processed securely");
                        })
                    )
                );
            }
        }
    }
    
    public static void good_case_13() {
        // Apache Tomcat - Using request attributes instead of InheritableThreadLocal
        class SecurityFilter implements javax.servlet.Filter {
            @Override
            public void doFilter(javax.servlet.ServletRequest request, 
                                javax.servlet.ServletResponse response, 
                                javax.servlet.FilterChain chain) throws java.io.IOException, javax.servlet.ServletException {
                
                javax.servlet.http.HttpServletRequest httpRequest = (javax.servlet.http.HttpServletRequest) request;
                String role = httpRequest.getHeader("X-User-Role");
                
                // Store in request attribute instead of ThreadLocal
                // ok: java-inheritable-thread-local
                httpRequest.setAttribute("userRole", role);
                
                // Async processing in Tomcat with proper context
                request.startAsync().start(() -> {
                    String requestRole = (String) httpRequest.getAttribute("userRole");
                    System.out.println("Processing as role: " + requestRole);
                });
                
                chain.doFilter(request, response);
            }
            
            // Other filter methods omitted for brevity
        }
    }
    
    public static void good_case_14() {
        // Undertow - Using exchange attachments instead of InheritableThreadLocal
        class TracingHandler implements io.undertow.server.HttpHandler {
            @Override
            public void handleRequest(io.undertow.server.HttpServerExchange exchange) throws Exception {
                if (exchange.isInIoThread()) {
                    exchange.dispatch(this);
                    return;
                }
                
                String requestTraceId = exchange.getRequestHeaders().getFirst("X-Trace-ID");
                
                // Store in exchange attachment instead of ThreadLocal
                // ok: java-inheritable-thread-local
                exchange.putAttachment(io.undertow.util.AttachmentKey.create(String.class), requestTraceId);
                
                // Worker thread processing with proper context
                exchange.getConnection().getWorker().execute(() -> {
                    String traceId = exchange.getAttachment(io.undertow.util.AttachmentKey.create(String.class));
                    System.out.println("Processing trace: " + traceId);
                });
                
                exchange.getResponseSender().send("Request traced securely");
            }
        }
    }
    
    public static void good_case_15() {
        // Jetty - Using request attributes instead of InheritableThreadLocal
        class TransactionHandler extends org.eclipse.jetty.server.handler.AbstractHandler {
            @Override
            public void handle(String target, 
                              org.eclipse.jetty.server.Request baseRequest, 
                              javax.servlet.http.HttpServletRequest request, 
                              javax.servlet.http.HttpServletResponse response) throws java.io.IOException, javax.servlet.ServletException {
                
                String txId = request.getHeader("X-Transaction-ID");
                
                // Store in request attribute instead of ThreadLocal
                // ok: java-inheritable-thread-local
                request.setAttribute("transactionId", txId);
                
                // Async processing in Jetty with proper context
                baseRequest.startAsync();
                new Thread(() -> {
                    try {
                        String transactionId = (String) request.getAttribute("transactionId");
                        System.out.println("Processing transaction: " + transactionId);
                        response.getWriter().println("Transaction processed securely");
                        baseRequest.getAsyncContext().complete();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();
                
                baseRequest.setHandled(true);
            }
        }
    }
}
// {/fact}