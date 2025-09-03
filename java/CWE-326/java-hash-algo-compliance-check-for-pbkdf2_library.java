import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.SecureRandom;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.Context;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.client.WebClient;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import retrofit2.Retrofit;
import retrofit2.Call;
import retrofit2.Callback;
import spark.Request;
import spark.Response;
import spark.Spark;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

// Security Issue: Insecure use of javax.crypto.SecretKeyFactory API where getInstance is called but not used

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    try {
        String password = request.getParameter("password");
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int iterations = 10000;
        int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        
        // ruleid: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // The SecretKeyFactory instance is created but never used
        
        // Some other code that doesn't use the factory
        byte[] hashedPassword = password.getBytes();
        System.out.println("Password processed");
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void bad_case_2(@RequestBody String requestBody) {
    try {
        // Spring MVC controller handling password reset
        String password = requestBody;
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        
        // ruleid: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        // Factory is instantiated but not assigned to a variable or used
        
        // Using an insecure method instead
        String hashedPassword = Base64.getEncoder().encodeToString(password.getBytes());
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    try {
        // OkHttp client to get password from remote service
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/user/password")
            .build();
            
        try (Response response = client.newCall(request).execute()) {
            String password = response.body().string();
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            // Factory instantiated but not used
            
            // Using another approach instead
            System.out.println("Password received: " + password);
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4(APIGatewayProxyRequestEvent event, Context context) {
    try {
        // AWS Lambda function handling user registration
        String password = event.getBody();
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        
        // ruleid: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // Factory instantiated but never used
        
        // Using a different approach
        String encodedPassword = Base64.getEncoder().encodeToString(password.getBytes());
        context.getLogger().log("User registered with encoded password");
    } catch (NoSuchAlgorithmException e) {
        context.getLogger().log("Error: " + e.getMessage());
    }
}

public void bad_case_5() {
    try {
        // Google HTTP Client for fetching credentials
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        com.google.api.client.http.HttpRequest request = requestFactory.buildGetRequest(
            new GenericUrl("https://api.example.com/credentials"));
        String password = request.execute().parseAsString();
        
        // ruleid: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        // Factory instantiated but not used
        
        System.out.println("Retrieved password: " + password);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6() {
    // Vertx web handler for user authentication
    Vertx vertx = Vertx.vertx();
    Router router = Router.router(vertx);
    
    router.post("/login").handler(ctx -> {
        try {
            String password = ctx.request().getFormAttribute("password");
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            // Factory instantiated but not used
            
            ctx.response().end("Login processed");
        } catch (NoSuchAlgorithmException e) {
            ctx.fail(e);
        }
    });
}

public void bad_case_7() {
    try {
        // Micronaut HTTP client for password validation
        HttpClient client = HttpClient.create("https://api.example.com");
        HttpRequest<String> request = HttpRequest.GET("/validate");
        String password = client.toBlocking().retrieve(request);
        
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        
        // ruleid: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        // Factory instantiated but not used
        
        System.out.println("Password validated");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    try {
        // RESTEasy client for user registration
        ResteasyClient client = new ResteasyClientBuilder().build();
        javax.ws.rs.client.WebTarget target = client.target("https://api.example.com/register");
        String password = target.request().get(String.class);
        
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        
        // ruleid: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        // Factory instantiated but not used
        
        System.out.println("User registered");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    // Retrofit client for password reset
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl("https://api.example.com/")
        .build();
    
    // Assume PasswordService is defined elsewhere
    PasswordService service = retrofit.create(PasswordService.class);
    
    service.resetPassword("newPassword").enqueue(new Callback<String>() {
        @Override
        public void onResponse(Call<String> call, retrofit2.Response<String> response) {
            try {
                String password = response.body();
                byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                
                // ruleid: java-hash-algo-compliance-check-for-pbkdf2
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                // Factory instantiated but not used
                
                System.out.println("Password reset successful");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        
        @Override
        public void onFailure(Call<String> call, Throwable t) {
            t.printStackTrace();
        }
    });
}

public void bad_case_10() {
    // Spark framework for password change endpoint
    Spark.post("/change-password", (Request request, Response response) -> {
        try {
            String password = request.body();
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            
            // ruleid: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            // Factory instantiated but not used
            
            return "Password changed successfully";
        } catch (NoSuchAlgorithmException e) {
            response.status(500);
            return "Error: " + e.getMessage();
        }
    });
}

public void bad_case_11() {
    // Jetty server handler for credential processing
    Server server = new Server(8080);
    server.setHandler(new AbstractHandler() {
        @Override
        public void handle(String target, Request baseRequest, 
                          javax.servlet.http.HttpServletRequest request,
                          HttpServletResponse response) throws IOException {
            try {
                String password = request.getParameter("password");
                byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                
                // ruleid: java-hash-algo-compliance-check-for-pbkdf2
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                // Factory instantiated but not used
                
                response.setContentType("text/html");
                response.setStatus(HttpServletResponse.SC_OK);
                response.getWriter().println("Credentials processed");
                baseRequest.setHandled(true);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
    });
}

public void bad_case_12() {
    try {
        // Apache HttpClient for password verification
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://api.example.com/verify");
        HttpResponse response = httpClient.execute(httpPost);
        String password = EntityUtils.toString(response.getEntity());
        
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        
        // ruleid: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // Factory instantiated but not used
        
        System.out.println("Password verified");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13() {
    // Vertx web client for credential validation
    Vertx vertx = Vertx.vertx();
    WebClient client = WebClient.create(vertx);
    
    client.get(8080, "api.example.com", "/validate")
        .send(ar -> {
            if (ar.succeeded()) {
                try {
                    String password = ar.result().bodyAsString();
                    byte[] salt = new byte[16];
                    new SecureRandom().nextBytes(salt);
                    
                    // ruleid: java-hash-algo-compliance-check-for-pbkdf2
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
                    // Factory instantiated but not used
                    
                    System.out.println("Credentials validated");
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            }
        });
}

public void bad_case_14(@RequestParam String password) {
    try {
        // Spring MVC controller with request parameter
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        
        // ruleid: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        // Factory instantiated but not used
        
        // Using a different approach
        String hashedPassword = new String(password.getBytes(StandardCharsets.UTF_8));
        System.out.println("Password processed: " + hashedPassword);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    try {
        // Servlet API with header-based authentication
        String authHeader = request.getHeader("Authorization");
        String password = authHeader.substring("Basic ".length());
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        
        // ruleid: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // Factory instantiated but not used
        
        System.out.println("Authentication processed");
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    try {
        String password = request.getParameter("password");
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int iterations = 10000;
        int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        
        // ok: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(spec);
        byte[] hashedPassword = key.getEncoded();
        
        System.out.println("Password securely hashed");
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
        e.printStackTrace();
    }
}

public void good_case_2(@RequestBody String requestBody) {
    try {
        // Spring MVC controller handling password reset
        String password = requestBody;
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int iterations = 10000;
        int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        
        // ok: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        
        System.out.println("Password reset processed securely");
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    try {
        // OkHttp client to get password from remote service
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/user/password")
            .build();
            
        try (Response response = client.newCall(request).execute()) {
            String password = response.body().string();
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            int iterations = 10000;
            int keyLength = 512;
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
            
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
            
            System.out.println("Password securely processed");
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4(APIGatewayProxyRequestEvent event, Context context) {
    try {
        // AWS Lambda function handling user registration
        String password = event.getBody();
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int iterations = 10000;
        int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        
        // ok: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        
        context.getLogger().log("User registered with secure password hash");
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
        context.getLogger().log("Error: " + e.getMessage());
    }
}

public void good_case_5() {
    try {
        // Google HTTP Client for fetching credentials
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        com.google.api.client.http.HttpRequest request = requestFactory.buildGetRequest(
            new GenericUrl("https://api.example.com/credentials"));
        String password = request.execute().parseAsString();
        
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int iterations = 10000;
        int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        
        // ok: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        
        System.out.println("Retrieved and securely hashed password");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6() {
    // Vertx web handler for user authentication
    Vertx vertx = Vertx.vertx();
    Router router = Router.router(vertx);
    
    router.post("/login").handler(ctx -> {
        try {
            String password = ctx.request().getFormAttribute("password");
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            int iterations = 10000;
            int keyLength = 256;
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
            
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
            
            ctx.response().end("Login processed securely");
        } catch (Exception e) {
            ctx.fail(e);
        }
    });
}

public void good_case_7() {
    try {
        // Micronaut HTTP client for password validation
        HttpClient client = HttpClient.create("https://api.example.com");
        HttpRequest<String> request = HttpRequest.GET("/validate");
        String password = client.toBlocking().retrieve(request);
        
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int iterations = 10000;
        int keyLength = 512;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        
        // ok: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        
        System.out.println("Password validated and securely hashed");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    try {
        // RESTEasy client for user registration
        ResteasyClient client = new ResteasyClientBuilder().build();
        javax.ws.rs.client.WebTarget target = client.target("https://api.example.com/register");
        String password = target.request().get(String.class);
        
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int iterations = 10000;
        int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        
        // ok: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        
        System.out.println("User registered with secure password");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    // Retrofit client for password reset
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl("https://api.example.com/")
        .build();
    
    // Assume PasswordService is defined elsewhere
    PasswordService service = retrofit.create(PasswordService.class);
    
    service.resetPassword("newPassword").enqueue(new Callback<String>() {
        @Override
        public void onResponse(Call<String> call, retrofit2.Response<String> response) {
            try {
                String password = response.body();
                byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                int iterations = 10000;
                int keyLength = 256;
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
                
                // ok: java-hash-algo-compliance-check-for-pbkdf2
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
                
                System.out.println("Password reset successful with secure hashing");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        @Override
        public void onFailure(Call<String> call, Throwable t) {
            t.printStackTrace();
        }
    });
}

public void good_case_10() {
    // Spark framework for password change endpoint
    Spark.post("/change-password", (Request request, Response response) -> {
        try {
            String password = request.body();
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            int iterations = 10000;
            int keyLength = 512;
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
            
            // ok: java-hash-algo-compliance-check-for-pbkdf2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
            
            return "Password changed successfully with secure hashing";
        } catch (Exception e) {
            response.status(500);
            return "Error: " + e.getMessage();
        }
    });
}

public void good_case_11() {
    // Jetty server handler for credential processing
    Server server = new Server(8080);
    server.setHandler(new AbstractHandler() {
        @Override
        public void handle(String target, Request baseRequest, 
                          javax.servlet.http.HttpServletRequest request,
                          HttpServletResponse response) throws IOException {
            try {
                String password = request.getParameter("password");
                byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                int iterations = 10000;
                int keyLength = 256;
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
                
                // ok: java-hash-algo-compliance-check-for-pbkdf2
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
                
                response.setContentType("text/html");
                response.setStatus(HttpServletResponse.SC_OK);
                response.getWriter().println("Credentials processed securely");
                baseRequest.setHandled(true);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    });
}

public void good_case_12() {
    try {
        // Apache HttpClient for password verification
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("https://api.example.com/verify");
        HttpResponse response = httpClient.execute(httpPost);
        String password = EntityUtils.toString(response.getEntity());
        
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int iterations = 10000;
        int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        
        // ok: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        
        System.out.println("Password verified and securely hashed");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13() {
    // Vertx web client for credential validation
    Vertx vertx = Vertx.vertx();
    WebClient client = WebClient.create(vertx);
    
    client.get(8080, "api.example.com", "/validate")
        .send(ar -> {
            if (ar.succeeded()) {
                try {
                    String password = ar.result().bodyAsString();
                    byte[] salt = new byte[16];
                    new SecureRandom().nextBytes(salt);
                    int iterations = 10000;
                    int keyLength = 512;
                    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
                    
                    // ok: java-hash-algo-compliance-check-for-pbkdf2
                    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
                    byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
                    
                    System.out.println("Credentials validated and securely hashed");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
}

public void good_case_14(@RequestParam String password) {
    try {
        // Spring MVC controller with request parameter
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int iterations = 10000;
        int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        
        // ok: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        
        System.out.println("Password processed securely");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    try {
        // Servlet API with header-based authentication
        String authHeader = request.getHeader("Authorization");
        String password = authHeader.substring("Basic ".length());
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        int iterations = 10000;
        int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        
        // ok: java-hash-algo-compliance-check-for-pbkdf2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        
        System.out.println("Authentication processed securely");
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Interface for Retrofit example
interface PasswordService {
    Call<String> resetPassword(String newPassword);
}