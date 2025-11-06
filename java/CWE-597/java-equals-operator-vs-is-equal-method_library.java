import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import retrofit2.Call;
import retrofit2.Callback;

import org.apache.struts2.ServletActionContext;
import org.apache.struts2.convention.annotation.Action;

import play.mvc.Controller;
import play.mvc.Result;

import spark.Route;
import spark.Spark;

import io.javalin.Javalin;
import io.javalin.http.Context;

import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;

import com.azure.core.http.rest.Response;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobServiceClient;

import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;

import org.apache.commons.lang3.StringUtils;

// Security Issue: Using the == operator for string comparison can lead to unexpected results due to potential reference mismatches,
// potentially causing security vulnerabilities like authentication bypasses or information disclosure.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // Spring MVC web framework - Authentication bypass vulnerability
    String expectedUsername = "admin";
    String expectedPassword = "secure_password";
    
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    
    // ruleid: java-equals-operator-vs-is-equal-method
    if (username == expectedUsername && password == expectedPassword) {
        System.out.println("Authentication successful");
        // Grant admin access
    } else {
        System.out.println("Authentication failed");
    }
}

public void bad_case_2() {
    // OkHttp client library - Insecure token validation
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url("https://api.example.com/auth")
        .build();
    
    try (Response response = client.newCall(request).execute()) {
        String token = response.header("Authorization");
        String expectedToken = "Bearer valid-token";
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (token == expectedToken) {
            System.out.println("Token is valid");
        } else {
            System.out.println("Invalid token");
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_3(HttpServletRequest request) {
    // Apache HttpClient - Insecure role-based access control
    String userRole = request.getParameter("role");
    String adminRole = "ADMIN";
    
    // ruleid: java-equals-operator-vs-is-equal-method
    if (userRole == adminRole) {
        System.out.println("Admin access granted");
        // Perform admin operations
    } else {
        System.out.println("Access denied");
    }
}

public void bad_case_4(Context context) {
    // AWS Lambda SDK - Insecure API key validation
    Map<String, String> headers = new HashMap<>();
    headers.put("x-api-key", "request-api-key");
    
    String expectedApiKey = "valid-api-key";
    String providedApiKey = headers.get("x-api-key");
    
    // ruleid: java-equals-operator-vs-is-equal-method
    if (providedApiKey == expectedApiKey) {
        System.out.println("API key is valid");
        // Process request
    } else {
        System.out.println("Invalid API key");
    }
}

public void bad_case_5() {
    // Retrofit API client - Insecure content type validation
    retrofit2.Response<String> response = null;
    try {
        response = getApiResponse().execute();
    } catch (IOException e) {
        e.printStackTrace();
    }
    
    if (response != null) {
        String contentType = response.headers().get("Content-Type");
        String expectedType = "application/json";
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (contentType == expectedType) {
            System.out.println("Valid content type");
        } else {
            System.out.println("Invalid content type");
        }
    }
}

public String bad_case_6() {
    // Apache Struts 2 - Insecure action validation
    String action = ServletActionContext.getRequest().getParameter("action");
    String expectedAction = "delete";
    
    // ruleid: java-equals-operator-vs-is-equal-method
    if (action == expectedAction) {
        return "success";
    } else {
        return "error";
    }
}

public void bad_case_7() {
    // Play Framework - Insecure session validation
    play.mvc.Http.Request request = play.mvc.Http.Context.current().request();
    String sessionId = request.getHeader("Session-ID");
    String validSessionId = "valid-session";
    
    // ruleid: java-equals-operator-vs-is-equal-method
    if (sessionId == validSessionId) {
        System.out.println("Valid session");
    } else {
        System.out.println("Invalid session");
    }
}

public void bad_case_8() {
    // Spark Java - Insecure parameter validation
    Spark.get("/api", (req, res) -> {
        String action = req.queryParams("action");
        String expectedAction = "update";
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (action == expectedAction) {
            return "Action permitted";
        } else {
            return "Action denied";
        }
    });
}

public void bad_case_9() {
    // Javalin - Insecure path validation
    Javalin app = Javalin.create().start(7000);
    app.get("/secure", ctx -> {
        String path = ctx.path();
        String securePath = "/secure";
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (path == securePath) {
            ctx.result("Access granted");
        } else {
            ctx.result("Access denied");
        }
    });
}

public void bad_case_10() {
    // Vert.x - Insecure header validation
    Vertx vertx = Vertx.vertx();
    Router router = Router.router(vertx);
    
    router.route("/api").handler(routingContext -> {
        String authHeader = routingContext.request().getHeader("Authorization");
        String expectedHeader = "Bearer token";
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (authHeader == expectedHeader) {
            routingContext.response().end("Authorized");
        } else {
            routingContext.response().end("Unauthorized");
        }
    });
}

public void bad_case_11() {
    // Google HTTP Client - Insecure URL validation
    try {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        com.google.api.client.http.HttpRequest request = requestFactory.buildGetRequest(
            new GenericUrl("https://api.example.com")
        );
        
        String url = request.getUrl().toString();
        String expectedUrl = "https://api.example.com";
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (url == expectedUrl) {
            System.out.println("URL is valid");
        } else {
            System.out.println("URL is invalid");
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    // AWS SDK v2 - Insecure bucket name validation
    S3Client s3Client = S3Client.builder().build();
    GetObjectRequest request = GetObjectRequest.builder()
        .bucket("user-input-bucket")
        .key("file.txt")
        .build();
    
    String bucketName = request.bucket();
    String allowedBucket = "allowed-bucket";
    
    // ruleid: java-equals-operator-vs-is-equal-method
    if (bucketName == allowedBucket) {
        System.out.println("Bucket access allowed");
    } else {
        System.out.println("Bucket access denied");
    }
}

public void bad_case_13() {
    // Azure SDK - Insecure blob name validation
    BlobClient blobClient = null; // Assume this is initialized
    String blobName = blobClient.getBlobName();
    String expectedName = "sensitive-data.txt";
    
    // ruleid: java-equals-operator-vs-is-equal-method
    if (blobName == expectedName) {
        System.out.println("Processing sensitive blob");
    } else {
        System.out.println("Unknown blob");
    }
}

public void bad_case_14() {
    // Google Cloud Storage - Insecure object name validation
    Storage storage = StorageOptions.getDefaultInstance().getService();
    String objectName = "user-provided-name.txt";
    String restrictedName = "system-config.txt";
    
    // ruleid: java-equals-operator-vs-is-equal-method
    if (objectName == restrictedName) {
        System.out.println("Access to restricted object denied");
    } else {
        System.out.println("Object access granted");
    }
}

public void bad_case_15(HttpServletRequest request, HttpServletResponse response) {
    // Java Servlet - Insecure method validation
    String method = request.getMethod();
    String allowedMethod = "POST";
    
    // ruleid: java-equals-operator-vs-is-equal-method
    if (method == allowedMethod) {
        try {
            response.getWriter().write("Method allowed");
        } catch (IOException e) {
            e.printStackTrace();
        }
    } else {
        try {
            response.getWriter().write("Method not allowed");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Spring MVC web framework - Secure authentication
    String expectedUsername = "admin";
    String expectedPassword = "secure_password";
    
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    
    // ok: java-equals-operator-vs-is-equal-method
    if (expectedUsername.equals(username) && expectedPassword.equals(password)) {
        System.out.println("Authentication successful");
        // Grant admin access
    } else {
        System.out.println("Authentication failed");
    }
}

public void good_case_2() {
    // OkHttp client library - Secure token validation
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url("https://api.example.com/auth")
        .build();
    
    try (Response response = client.newCall(request).execute()) {
        String token = response.header("Authorization");
        String expectedToken = "Bearer valid-token";
        
        // ok: java-equals-operator-vs-is-equal-method
        if (expectedToken.equals(token)) {
            System.out.println("Token is valid");
        } else {
            System.out.println("Invalid token");
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_3(HttpServletRequest request) {
    // Apache HttpClient - Secure role-based access control
    String userRole = request.getParameter("role");
    String adminRole = "ADMIN";
    
    // ok: java-equals-operator-vs-is-equal-method
    if (adminRole.equals(userRole)) {
        System.out.println("Admin access granted");
        // Perform admin operations
    } else {
        System.out.println("Access denied");
    }
}

public void good_case_4(Context context) {
    // AWS Lambda SDK - Secure API key validation
    Map<String, String> headers = new HashMap<>();
    headers.put("x-api-key", "request-api-key");
    
    String expectedApiKey = "valid-api-key";
    String providedApiKey = headers.get("x-api-key");
    
    // ok: java-equals-operator-vs-is-equal-method
    if (expectedApiKey.equals(providedApiKey)) {
        System.out.println("API key is valid");
        // Process request
    } else {
        System.out.println("Invalid API key");
    }
}

public void good_case_5() {
    // Retrofit API client - Secure content type validation
    retrofit2.Response<String> response = null;
    try {
        response = getApiResponse().execute();
    } catch (IOException e) {
        e.printStackTrace();
    }
    
    if (response != null) {
        String contentType = response.headers().get("Content-Type");
        String expectedType = "application/json";
        
        // ok: java-equals-operator-vs-is-equal-method
        if (expectedType.equals(contentType)) {
            System.out.println("Valid content type");
        } else {
            System.out.println("Invalid content type");
        }
    }
}

public String good_case_6() {
    // Apache Struts 2 - Secure action validation
    String action = ServletActionContext.getRequest().getParameter("action");
    String expectedAction = "delete";
    
    // ok: java-equals-operator-vs-is-equal-method
    if (expectedAction.equals(action)) {
        return "success";
    } else {
        return "error";
    }
}

public void good_case_7() {
    // Play Framework - Secure session validation
    play.mvc.Http.Request request = play.mvc.Http.Context.current().request();
    String sessionId = request.getHeader("Session-ID");
    String validSessionId = "valid-session";
    
    // ok: java-equals-operator-vs-is-equal-method
    if (validSessionId.equals(sessionId)) {
        System.out.println("Valid session");
    } else {
        System.out.println("Invalid session");
    }
}

public void good_case_8() {
    // Spark Java - Secure parameter validation
    Spark.get("/api", (req, res) -> {
        String action = req.queryParams("action");
        String expectedAction = "update";
        
        // ok: java-equals-operator-vs-is-equal-method
        if (expectedAction.equals(action)) {
            return "Action permitted";
        } else {
            return "Action denied";
        }
    });
}

public void good_case_9() {
    // Javalin - Secure path validation
    Javalin app = Javalin.create().start(7000);
    app.get("/secure", ctx -> {
        String path = ctx.path();
        String securePath = "/secure";
        
        // ok: java-equals-operator-vs-is-equal-method
        if (securePath.equals(path)) {
            ctx.result("Access granted");
        } else {
            ctx.result("Access denied");
        }
    });
}

public void good_case_10() {
    // Vert.x - Secure header validation
    Vertx vertx = Vertx.vertx();
    Router router = Router.router(vertx);
    
    router.route("/api").handler(routingContext -> {
        String authHeader = routingContext.request().getHeader("Authorization");
        String expectedHeader = "Bearer token";
        
        // ok: java-equals-operator-vs-is-equal-method
        if (expectedHeader.equals(authHeader)) {
            routingContext.response().end("Authorized");
        } else {
            routingContext.response().end("Unauthorized");
        }
    });
}

public void good_case_11() {
    // Google HTTP Client - Secure URL validation
    try {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        com.google.api.client.http.HttpRequest request = requestFactory.buildGetRequest(
            new GenericUrl("https://api.example.com")
        );
        
        String url = request.getUrl().toString();
        String expectedUrl = "https://api.example.com";
        
        // ok: java-equals-operator-vs-is-equal-method
        if (expectedUrl.equals(url)) {
            System.out.println("URL is valid");
        } else {
            System.out.println("URL is invalid");
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void good_case_12() {
    // AWS SDK v2 - Secure bucket name validation
    S3Client s3Client = S3Client.builder().build();
    GetObjectRequest request = GetObjectRequest.builder()
        .bucket("user-input-bucket")
        .key("file.txt")
        .build();
    
    String bucketName = request.bucket();
    String allowedBucket = "allowed-bucket";
    
    // ok: java-equals-operator-vs-is-equal-method
    if (allowedBucket.equals(bucketName)) {
        System.out.println("Bucket access allowed");
    } else {
        System.out.println("Bucket access denied");
    }
}

public void good_case_13() {
    // Azure SDK - Secure blob name validation
    BlobClient blobClient = null; // Assume this is initialized
    String blobName = blobClient.getBlobName();
    String expectedName = "sensitive-data.txt";
    
    // ok: java-equals-operator-vs-is-equal-method
    if (expectedName.equals(blobName)) {
        System.out.println("Processing sensitive blob");
    } else {
        System.out.println("Unknown blob");
    }
}

public void good_case_14() {
    // Google Cloud Storage - Secure object name validation with null check
    Storage storage = StorageOptions.getDefaultInstance().getService();
    String objectName = "user-provided-name.txt";
    String restrictedName = "system-config.txt";
    
    // ok: java-equals-operator-vs-is-equal-method
    if (restrictedName.equals(objectName)) {
        System.out.println("Access to restricted object denied");
    } else {
        System.out.println("Object access granted");
    }
}

public void good_case_15(HttpServletRequest request, HttpServletResponse response) {
    // Java Servlet - Secure method validation using StringUtils
    String method = request.getMethod();
    String allowedMethod = "POST";
    
    // ok: java-equals-operator-vs-is-equal-method
    if (StringUtils.equals(method, allowedMethod)) {
        try {
            response.getWriter().write("Method allowed");
        } catch (IOException e) {
            e.printStackTrace();
        }
    } else {
        try {
            response.getWriter().write("Method not allowed");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// Helper method for Retrofit examples
private Call<String> getApiResponse() {
    return null; // This would be implemented with actual Retrofit code
}