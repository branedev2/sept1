import java.util.Optional;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.io.IOException;

// Spring Framework imports
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.data.repository.CrudRepository;

// JAX-RS imports
import javax.ws.rs.*;
import javax.ws.rs.core.Response;

// Retrofit imports
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

// AWS SDK imports
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

// Guava imports
import com.google.common.base.Optional; // Guava's Optional

// Jackson imports
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

// OkHttp imports
import okhttp3.OkHttpClient;
import okhttp3.Request;

// Hibernate imports
import org.hibernate.Session;
import org.hibernate.SessionFactory;

// Micronaut imports
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

// Quarkus imports
import io.quarkus.hibernate.orm.panache.PanacheRepository;

// Vert.x imports
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

// Javalin imports
import io.javalin.Javalin;
import io.javalin.http.Context;

// Security Issue: Unsafe access to Optional values without checking if they are present

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Spring Web MVC example - Unsafe Optional access with request parameter
    String userId = request.getParameter("userId");
    Optional<User> userOpt = userRepository.findById(userId);
    // ruleid: java-optional-value-access
    User user = userOpt.get(); // Unsafe: No check if present before get()
    System.out.println("User name: " + user.getName());
}

public void bad_case_2() {
    // JAX-RS example - Unsafe Optional access with path parameter
    @Path("/users/{id}")
    @GET
    public Response getUser(@PathParam("id") String id) {
        Optional<User> userOpt = userService.findUserById(id);
        // ruleid: java-optional-value-access
        return Response.ok(userOpt.get()).build(); // Unsafe: Direct get() without check
    }
}

public void bad_case_3() {
    // Retrofit example - Unsafe Optional access in API client response
    Call<Optional<Product>> call = apiService.getProduct(productId);
    call.enqueue(new Callback<Optional<Product>>() {
        @Override
        public void onResponse(Call<Optional<Product>> call, Response<Optional<Product>> response) {
            Optional<Product> productOpt = response.body();
            // ruleid: java-optional-value-access
            Product product = productOpt.get(); // Unsafe: No check if present
            updateUI(product);
        }
        
        @Override
        public void onFailure(Call<Optional<Product>> call, Throwable t) {
            handleError(t);
        }
    });
}

public void bad_case_4() {
    // AWS SDK example - Unsafe Optional access with S3 object
    S3Client s3Client = S3Client.builder().build();
    GetObjectRequest request = GetObjectRequest.builder()
            .bucket("my-bucket")
            .key("my-key")
            .build();
    
    Optional<GetObjectResponse> responseOpt = Optional.ofNullable(
            s3Client.getObject(request, (response) -> {
                // Process response
            })
    );
    
    // ruleid: java-optional-value-access
    GetObjectResponse response = responseOpt.get(); // Unsafe: Direct get() without check
    System.out.println("Content length: " + response.contentLength());
}

public void bad_case_5() {
    // Guava Optional example - Unsafe access in HTTP client
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
            .url("https://api.example.com/data")
            .build();
    
    try {
        okhttp3.Response response = client.newCall(request).execute();
        com.google.common.base.Optional<String> bodyOpt = 
                com.google.common.base.Optional.fromNullable(response.body().string());
        // ruleid: java-optional-value-access
        String body = bodyOpt.get(); // Unsafe: Direct get() without check
        processData(body);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    // Jackson JSON parsing with Optional - Unsafe access
    ObjectMapper mapper = new ObjectMapper();
    String json = "{\"data\": {\"value\": 42}}";
    
    try {
        JsonNode rootNode = mapper.readTree(json);
        Optional<JsonNode> dataNodeOpt = Optional.ofNullable(rootNode.get("data"));
        // ruleid: java-optional-value-access
        JsonNode dataNode = dataNodeOpt.get(); // Unsafe: Direct get() without check
        int value = dataNode.get("value").asInt();
        System.out.println("Value: " + value);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    // Hibernate ORM example - Unsafe Optional access with entity
    Session session = sessionFactory.openSession();
    Optional<Customer> customerOpt = Optional.ofNullable(
            session.get(Customer.class, customerId));
    
    // ruleid: java-optional-value-access
    Customer customer = customerOpt.get(); // Unsafe: Direct get() without check
    processCustomerData(customer);
    session.close();
}

public void bad_case_8() {
    // Micronaut framework example - Unsafe Optional access with HTTP request
    @Controller("/api")
    public class ProductController {
        @Get("/{id}")
        public HttpResponse<Product> getProduct(String id, HttpRequest<?> request) {
            Optional<Product> productOpt = productRepository.findById(id);
            // ruleid: java-optional-value-access
            Product product = productOpt.get(); // Unsafe: Direct get() without check
            return HttpResponse.ok(product);
        }
    }
}

public void bad_case_9() {
    // Quarkus Panache repository example - Unsafe Optional access
    class UserRepository implements PanacheRepository<User> {
        public User findByUsername(String username) {
            Optional<User> userOpt = find("username", username).firstResultOptional();
            // ruleid: java-optional-value-access
            return userOpt.get(); // Unsafe: Direct get() without check
        }
    }
}

public void bad_case_10() {
    // Vert.x web example - Unsafe Optional access with request parameter
    Router router = Router.router(vertx);
    router.get("/api/users/:id").handler(routingContext -> {
        String userId = routingContext.request().getParam("id");
        Optional<User> userOpt = userService.findById(userId);
        // ruleid: java-optional-value-access
        User user = userOpt.get(); // Unsafe: Direct get() without check
        routingContext.json(user);
    });
}

public void bad_case_11() {
    // Javalin web framework example - Unsafe Optional access
    Javalin app = Javalin.create().start(7000);
    app.get("/users/:id", ctx -> {
        String userId = ctx.pathParam("id");
        Optional<User> userOpt = userDao.findById(userId);
        // ruleid: java-optional-value-access
        ctx.json(userOpt.get()); // Unsafe: Direct get() without check
    });
}

public void bad_case_12() {
    // CompletableFuture with Optional - Unsafe access
    CompletableFuture<Optional<Order>> futureOrder = orderService.findOrderByIdAsync(orderId);
    futureOrder.thenAccept(orderOpt -> {
        // ruleid: java-optional-value-access
        Order order = orderOpt.get(); // Unsafe: Direct get() without check
        processOrder(order);
    });
}

public void bad_case_13() {
    // Stream API with Optional - Unsafe access
    List<String> userIds = getUserIdsFromRequest(request);
    List<User> users = userIds.stream()
        .map(id -> userRepository.findById(id))
        .map(userOpt -> {
            // ruleid: java-optional-value-access
            return userOpt.get(); // Unsafe: Direct get() without check
        })
        .collect(Collectors.toList());
    
    processUsers(users);
}

public void bad_case_14() {
    // Spring Data JPA repository example - Unsafe Optional access
    interface ProductRepository extends CrudRepository<Product, Long> {
        Optional<Product> findBySku(String sku);
    }
    
    @GetMapping("/products/sku/{sku}")
    public ResponseEntity<Product> getProductBySku(@PathVariable String sku) {
        Optional<Product> productOpt = productRepository.findBySku(sku);
        // ruleid: java-optional-value-access
        Product product = productOpt.get(); // Unsafe: Direct get() without check
        return ResponseEntity.ok(product);
    }
}

public void bad_case_15() {
    // Custom HTTP client with Optional - Unsafe access
    HttpClient client = HttpClient.newHttpClient();
    HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.com/data"))
            .build();
    
    try {
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        Optional<String> bodyOpt = Optional.ofNullable(response.body());
        // ruleid: java-optional-value-access
        String body = bodyOpt.get(); // Unsafe: Direct get() without check
        processResponseData(body);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Spring Web MVC example - Safe Optional access with request parameter
    String userId = request.getParameter("userId");
    Optional<User> userOpt = userRepository.findById(userId);
    
    // ok: java-optional-value-access
    if (userOpt.isPresent()) {
        User user = userOpt.get();
        System.out.println("User name: " + user.getName());
    } else {
        System.out.println("User not found");
    }
}

public void good_case_2() {
    // JAX-RS example - Safe Optional access with path parameter
    @Path("/users/{id}")
    @GET
    public Response getUser(@PathParam("id") String id) {
        Optional<User> userOpt = userService.findUserById(id);
        
        // ok: java-optional-value-access
        return userOpt.isPresent() 
            ? Response.ok(userOpt.get()).build()
            : Response.status(Response.Status.NOT_FOUND).build();
    }
}

public void good_case_3() {
    // Retrofit example - Safe Optional access in API client response
    Call<Optional<Product>> call = apiService.getProduct(productId);
    call.enqueue(new Callback<Optional<Product>>() {
        @Override
        public void onResponse(Call<Optional<Product>> call, Response<Optional<Product>> response) {
            Optional<Product> productOpt = response.body();
            
            // ok: java-optional-value-access
            productOpt.ifPresent(product -> {
                updateUI(product);
            });
        }
        
        @Override
        public void onFailure(Call<Optional<Product>> call, Throwable t) {
            handleError(t);
        }
    });
}

public void good_case_4() {
    // AWS SDK example - Safe Optional access with S3 object
    S3Client s3Client = S3Client.builder().build();
    GetObjectRequest request = GetObjectRequest.builder()
            .bucket("my-bucket")
            .key("my-key")
            .build();
    
    Optional<GetObjectResponse> responseOpt = Optional.ofNullable(
            s3Client.getObject(request, (response) -> {
                // Process response
            })
    );
    
    // ok: java-optional-value-access
    responseOpt.ifPresent(response -> {
        System.out.println("Content length: " + response.contentLength());
    });
}

public void good_case_5() {
    // Guava Optional example - Safe access in HTTP client
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
            .url("https://api.example.com/data")
            .build();
    
    try {
        okhttp3.Response response = client.newCall(request).execute();
        com.google.common.base.Optional<String> bodyOpt = 
                com.google.common.base.Optional.fromNullable(response.body().string());
        
        // ok: java-optional-value-access
        if (bodyOpt.isPresent()) {
            String body = bodyOpt.get();
            processData(body);
        } else {
            handleEmptyResponse();
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    // Jackson JSON parsing with Optional - Safe access
    ObjectMapper mapper = new ObjectMapper();
    String json = "{\"data\": {\"value\": 42}}";
    
    try {
        JsonNode rootNode = mapper.readTree(json);
        Optional<JsonNode> dataNodeOpt = Optional.ofNullable(rootNode.get("data"));
        
        // ok: java-optional-value-access
        int value = dataNodeOpt
            .map(dataNode -> dataNode.get("value"))
            .map(JsonNode::asInt)
            .orElse(0);
        
        System.out.println("Value: " + value);
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    // Hibernate ORM example - Safe Optional access with entity
    Session session = sessionFactory.openSession();
    Optional<Customer> customerOpt = Optional.ofNullable(
            session.get(Customer.class, customerId));
    
    // ok: java-optional-value-access
    Customer customer = customerOpt.orElseGet(() -> {
        Customer defaultCustomer = new Customer();
        defaultCustomer.setName("Guest");
        return defaultCustomer;
    });
    
    processCustomerData(customer);
    session.close();
}

public void good_case_8() {
    // Micronaut framework example - Safe Optional access with HTTP request
    @Controller("/api")
    public class ProductController {
        @Get("/{id}")
        public HttpResponse<?> getProduct(String id, HttpRequest<?> request) {
            Optional<Product> productOpt = productRepository.findById(id);
            
            // ok: java-optional-value-access
            return productOpt
                .map(product -> HttpResponse.ok(product))
                .orElse(HttpResponse.notFound());
        }
    }
}

public void good_case_9() {
    // Quarkus Panache repository example - Safe Optional access
    class UserRepository implements PanacheRepository<User> {
        public User findByUsername(String username) {
            Optional<User> userOpt = find("username", username).firstResultOptional();
            
            // ok: java-optional-value-access
            return userOpt.orElseThrow(() -> 
                new NotFoundException("User not found with username: " + username));
        }
    }
}

public void good_case_10() {
    // Vert.x web example - Safe Optional access with request parameter
    Router router = Router.router(vertx);
    router.get("/api/users/:id").handler(routingContext -> {
        String userId = routingContext.request().getParam("id");
        Optional<User> userOpt = userService.findById(userId);
        
        // ok: java-optional-value-access
        if (userOpt.isPresent()) {
            routingContext.json(userOpt.get());
        } else {
            routingContext.response().setStatusCode(404).end();
        }
    });
}

public void good_case_11() {
    // Javalin web framework example - Safe Optional access
    Javalin app = Javalin.create().start(7000);
    app.get("/users/:id", ctx -> {
        String userId = ctx.pathParam("id");
        Optional<User> userOpt = userDao.findById(userId);
        
        // ok: java-optional-value-access
        userOpt.ifPresentOrElse(
            user -> ctx.json(user),
            () -> ctx.status(404).result("User not found")
        );
    });
}

public void good_case_12() {
    // CompletableFuture with Optional - Safe access
    CompletableFuture<Optional<Order>> futureOrder = orderService.findOrderByIdAsync(orderId);
    futureOrder.thenAccept(orderOpt -> {
        // ok: java-optional-value-access
        orderOpt.ifPresentOrElse(
            this::processOrder,
            () -> logOrderNotFound(orderId)
        );
    });
}

public void good_case_13() {
    // Stream API with Optional - Safe access
    List<String> userIds = getUserIdsFromRequest(request);
    List<User> users = userIds.stream()
        .map(id -> userRepository.findById(id))
        .filter(Optional::isPresent)
        // ok: java-optional-value-access
        .map(Optional::get)
        .collect(Collectors.toList());
    
    processUsers(users);
}

public void good_case_14() {
    // Spring Data JPA repository example - Safe Optional access
    interface ProductRepository extends CrudRepository<Product, Long> {
        Optional<Product> findBySku(String sku);
    }
    
    @GetMapping("/products/sku/{sku}")
    public ResponseEntity<Product> getProductBySku(@PathVariable String sku) {
        Optional<Product> productOpt = productRepository.findBySku(sku);
        
        // ok: java-optional-value-access
        return productOpt
            .map(ResponseEntity::ok)
            .orElseGet(() -> ResponseEntity.notFound().build());
    }
}

public void good_case_15() {
    // Custom HTTP client with Optional - Safe access
    HttpClient client = HttpClient.newHttpClient();
    HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.com/data"))
            .build();
    
    try {
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        Optional<String> bodyOpt = Optional.ofNullable(response.body());
        
        // ok: java-optional-value-access
        String body = bodyOpt.orElse("");
        if (!body.isEmpty()) {
            processResponseData(body);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}