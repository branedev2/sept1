import java.io.IOException;
import java.util.logging.Logger;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Retrofit;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.Channel;
import org.apache.commons.net.telnet.TelnetClient;
import com.azure.storage.blob.BlobServiceClient;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import software.amazon.awssdk.services.s3.S3Client;
import io.quarkus.runtime.annotations.QuarkusMain;
import io.quarkus.runtime.Quarkus;
import play.mvc.Controller;
import play.mvc.Result;
import spark.Spark;

// Security Issue: Using println() instead of dedicated logging facilities

// True Positive Examples (Vulnerable/Insecure Code)

public class PoorLoggingPracticeExamples {

// {fact rule=seven-pk-code-quality@v1.0 defects=1}
    public static void bad_case_1(HttpServletRequest request) {
        // Spring MVC web application using System.out.println for logging
        String username = request.getParameter("username");
        String action = request.getParameter("action");
        
        // ruleid: java-poor-logging-practice
        System.out.println("User " + username + " performed action: " + action);
        
        // Process user request
        if (action.equals("login")) {
            // Authentication logic
            // ruleid: java-poor-logging-practice
            System.out.println("Login attempt for user: " + username);
        }
    }
    
    public static void bad_case_2() {
        // Apache HttpClient with println logging
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.com/data");
            
            // ruleid: java-poor-logging-practice
            System.out.println("Sending request to: " + request.getURI());
            
            httpClient.execute(request);
            
            // ruleid: java-poor-logging-practice
            System.out.println("Request completed successfully");
        } catch (IOException e) {
            // ruleid: java-poor-logging-practice
            System.out.println("Error occurred: " + e.getMessage());
        }
    }
    
    public static void bad_case_3() {
        // OkHttp client with println logging
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/users")
            .build();
            
        try {
            // ruleid: java-poor-logging-practice
            System.out.println("Sending OkHttp request to fetch users");
            
            Response response = client.newCall(request).execute();
            
            // ruleid: java-poor-logging-practice
            System.out.println("Response received with code: " + response.code());
        } catch (IOException e) {
            // ruleid: java-poor-logging-practice
            System.out.println("OkHttp request failed: " + e.getMessage());
        }
    }
    
    public static void bad_case_4() {
        // Apache Commons Exec with println logging
        try {
            CommandLine cmdLine = CommandLine.parse("ls -la");
            DefaultExecutor executor = new DefaultExecutor();
            
            // ruleid: java-poor-logging-practice
            System.out.println("Executing command: " + cmdLine);
            
            int exitValue = executor.execute(cmdLine);
            
            // ruleid: java-poor-logging-practice
            System.out.println("Command executed with exit code: " + exitValue);
        } catch (IOException e) {
            // ruleid: java-poor-logging-practice
            System.out.println("Command execution failed: " + e.getMessage());
        }
    }
    
    public static void bad_case_5() {
        // JSch (SSH library) with println logging
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession("username", "hostname", 22);
            session.setPassword("password");
            
            // ruleid: java-poor-logging-practice
            System.out.println("Connecting to SSH server...");
            
            session.connect();
            Channel channel = session.openChannel("exec");
            
            // ruleid: java-poor-logging-practice
            System.out.println("SSH connection established");
            
            channel.disconnect();
            session.disconnect();
        } catch (Exception e) {
            // ruleid: java-poor-logging-practice
            System.out.println("SSH connection failed: " + e.getMessage());
        }
    }
    
    public static void bad_case_6() {
        // AWS S3 SDK with println logging
        try {
            S3Client s3Client = S3Client.builder().build();
            
            // ruleid: java-poor-logging-practice
            System.out.println("Listing S3 buckets");
            
            s3Client.listBuckets();
            
            // ruleid: java-poor-logging-practice
            System.out.println("S3 buckets listed successfully");
        } catch (Exception e) {
            // ruleid: java-poor-logging-practice
            System.out.println("Failed to list S3 buckets: " + e.getMessage());
        }
    }
    
    public static void bad_case_7(RoutingContext routingContext) {
        // Vert.x web framework with println logging
        String requestPath = routingContext.request().path();
        String method = routingContext.request().method().name();
        
        // ruleid: java-poor-logging-practice
        System.out.println("Received " + method + " request at path: " + requestPath);
        
        routingContext.response()
            .putHeader("content-type", "application/json")
            .end("{\"status\":\"success\"}");
            
        // ruleid: java-poor-logging-practice
        System.out.println("Response sent for request: " + requestPath);
    }
    
    public static void bad_case_8() {
        // Retrofit API client with println logging
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
            
        // ruleid: java-poor-logging-practice
        System.out.println("Initializing API client");
        
        // Make API call
        try {
            // API call simulation
            // ruleid: java-poor-logging-practice
            System.out.println("API call completed");
        } catch (Exception e) {
            // ruleid: java-poor-logging-practice
            System.out.println("API call failed: " + e.getMessage());
        }
    }
    
    public static void bad_case_9() {
        // Apache Commons Net (Telnet) with println logging
        TelnetClient telnet = new TelnetClient();
        try {
            // ruleid: java-poor-logging-practice
            System.out.println("Connecting to telnet server...");
            
            telnet.connect("hostname", 23);
            
            // ruleid: java-poor-logging-practice
            System.out.println("Telnet connection established");
            
            telnet.disconnect();
        } catch (IOException e) {
            // ruleid: java-poor-logging-practice
            System.out.println("Telnet connection failed: " + e.getMessage());
        }
    }
    
    public static void bad_case_10() {
        // Google Cloud Storage with println logging
        try {
            Storage storage = StorageOptions.getDefaultInstance().getService();
            
            // ruleid: java-poor-logging-practice
            System.out.println("Listing GCS buckets");
            
            storage.list();
            
            // ruleid: java-poor-logging-practice
            System.out.println("GCS buckets listed successfully");
        } catch (Exception e) {
            // ruleid: java-poor-logging-practice
            System.out.println("Failed to list GCS buckets: " + e.getMessage());
        }
    }
    
    public static void bad_case_11() {
        // Azure Blob Storage with println logging
        try {
            BlobServiceClient blobServiceClient = new BlobServiceClient.Builder()
                .connectionString("connection-string")
                .buildClient();
                
            // ruleid: java-poor-logging-practice
            System.out.println("Listing Azure blob containers");
            
            blobServiceClient.listBlobContainers();
            
            // ruleid: java-poor-logging-practice
            System.out.println("Azure blob containers listed successfully");
        } catch (Exception e) {
            // ruleid: java-poor-logging-practice
            System.out.println("Failed to list Azure containers: " + e.getMessage());
        }
    }
    
    @QuarkusMain
    public static class bad_case_12 {
        // Quarkus application with println logging
        public static void main(String[] args) {
            // ruleid: java-poor-logging-practice
            System.out.println("Starting Quarkus application");
            
            Quarkus.run(args);
            
            // ruleid: java-poor-logging-practice
            System.out.println("Quarkus application started");
        }
    }
    
    public static void bad_case_13(HttpServletRequest request) {
        // Play Framework with println logging
        String path = request.getRequestURI();
        
        // ruleid: java-poor-logging-practice
        System.out.println("Processing Play Framework request: " + path);
        
        // Process request
        
        // ruleid: java-poor-logging-practice
        System.out.println("Play Framework request processed: " + path);
    }
    
    public static void bad_case_14() {
        // Spark Java framework with println logging
        Spark.get("/hello", (req, res) -> {
            String ip = req.ip();
            
            // ruleid: java-poor-logging-practice
            System.out.println("Received request from IP: " + ip);
            
            return "Hello World";
        });
        
        // ruleid: java-poor-logging-practice
        System.out.println("Spark Java routes configured");
    }
    
    public static class bad_case_15 implements RequestHandler<Object, String> {
        // AWS Lambda with println logging
        @Override
        public String handleRequest(Object input, Context context) {
            // ruleid: java-poor-logging-practice
            System.out.println("Lambda function invoked with input: " + input);
            
            // Process the request
            
            // ruleid: java-poor-logging-practice
            System.out.println("Lambda function execution completed");
            
            return "Success";
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public static void good_case_1(HttpServletRequest request) {
        // Spring MVC web application using proper logging
        Logger logger = Logger.getLogger(PoorLoggingPracticeExamples.class.getName());
        
        String username = request.getParameter("username");
        String action = request.getParameter("action");
        
        // ok: java-poor-logging-practice
        logger.info("User " + username + " performed action: " + action);
        
        // Process user request
        if (action.equals("login")) {
            // Authentication logic
            // ok: java-poor-logging-practice
            logger.info("Login attempt for user: " + username);
        }
    }
    
    public static void good_case_2() {
        // Apache HttpClient with proper logging
        Logger logger = Logger.getLogger(PoorLoggingPracticeExamples.class.getName());
        
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet("https://api.example.com/data");
            
            // ok: java-poor-logging-practice
            logger.info("Sending request to: " + request.getURI());
            
            httpClient.execute(request);
            
            // ok: java-poor-logging-practice
            logger.info("Request completed successfully");
        } catch (IOException e) {
            // ok: java-poor-logging-practice
            logger.log(Level.SEVERE, "Error occurred", e);
        }
    }
    
    public static void good_case_3() {
        // OkHttp client with proper logging (SLF4J)
        org.slf4j.Logger logger = LoggerFactory.getLogger(PoorLoggingPracticeExamples.class);
        
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/users")
            .build();
            
        try {
            // ok: java-poor-logging-practice
            logger.info("Sending OkHttp request to fetch users");
            
            Response response = client.newCall(request).execute();
            
            // ok: java-poor-logging-practice
            logger.info("Response received with code: {}", response.code());
        } catch (IOException e) {
            // ok: java-poor-logging-practice
            logger.error("OkHttp request failed", e);
        }
    }
    
    public static void good_case_4() {
        // Apache Commons Exec with proper logging (Log4j2)
        org.apache.logging.log4j.Logger logger = LogManager.getLogger(PoorLoggingPracticeExamples.class);
        
        try {
            CommandLine cmdLine = CommandLine.parse("ls -la");
            DefaultExecutor executor = new DefaultExecutor();
            
            // ok: java-poor-logging-practice
            logger.info("Executing command: {}", cmdLine);
            
            int exitValue = executor.execute(cmdLine);
            
            // ok: java-poor-logging-practice
            logger.info("Command executed with exit code: {}", exitValue);
        } catch (IOException e) {
            // ok: java-poor-logging-practice
            logger.error("Command execution failed", e);
        }
    }
    
    public static void good_case_5() {
        // JSch (SSH library) with proper logging (Apache Commons Logging)
        Log log = LogFactory.getLog(PoorLoggingPracticeExamples.class);
        
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession("username", "hostname", 22);
            session.setPassword("password");
            
            // ok: java-poor-logging-practice
            log.info("Connecting to SSH server...");
            
            session.connect();
            Channel channel = session.openChannel("exec");
            
            // ok: java-poor-logging-practice
            log.info("SSH connection established");
            
            channel.disconnect();
            session.disconnect();
        } catch (Exception e) {
            // ok: java-poor-logging-practice
            log.error("SSH connection failed", e);
        }
    }
    
    public static void good_case_6() {
        // AWS S3 SDK with proper logging
        Logger logger = Logger.getLogger(PoorLoggingPracticeExamples.class.getName());
        
        try {
            S3Client s3Client = S3Client.builder().build();
            
            // ok: java-poor-logging-practice
            logger.info("Listing S3 buckets");
            
            s3Client.listBuckets();
            
            // ok: java-poor-logging-practice
            logger.info("S3 buckets listed successfully");
        } catch (Exception e) {
            // ok: java-poor-logging-practice
            logger.log(Level.SEVERE, "Failed to list S3 buckets", e);
        }
    }
    
    public static void good_case_7(RoutingContext routingContext) {
        // Vert.x web framework with proper logging (SLF4J)
        org.slf4j.Logger logger = LoggerFactory.getLogger(PoorLoggingPracticeExamples.class);
        
        String requestPath = routingContext.request().path();
        String method = routingContext.request().method().name();
        
        // ok: java-poor-logging-practice
        logger.info("Received {} request at path: {}", method, requestPath);
        
        routingContext.response()
            .putHeader("content-type", "application/json")
            .end("{\"status\":\"success\"}");
            
        // ok: java-poor-logging-practice
        logger.info("Response sent for request: {}", requestPath);
    }
    
    public static void good_case_8() {
        // Retrofit API client with proper logging (Log4j2)
        org.apache.logging.log4j.Logger logger = LogManager.getLogger(PoorLoggingPracticeExamples.class);
        
        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .build();
            
        // ok: java-poor-logging-practice
        logger.info("Initializing API client");
        
        // Make API call
        try {
            // API call simulation
            // ok: java-poor-logging-practice
            logger.info("API call completed");
        } catch (Exception e) {
            // ok: java-poor-logging-practice
            logger.error("API call failed", e);
        }
    }
    
    public static void good_case_9() {
        // Apache Commons Net (Telnet) with proper logging
        Logger logger = Logger.getLogger(PoorLoggingPracticeExamples.class.getName());
        
        TelnetClient telnet = new TelnetClient();
        try {
            // ok: java-poor-logging-practice
            logger.info("Connecting to telnet server...");
            
            telnet.connect("hostname", 23);
            
            // ok: java-poor-logging-practice
            logger.info("Telnet connection established");
            
            telnet.disconnect();
        } catch (IOException e) {
            // ok: java-poor-logging-practice
            logger.log(Level.SEVERE, "Telnet connection failed", e);
        }
    }
    
    public static void good_case_10() {
        // Google Cloud Storage with proper logging (SLF4J)
        org.slf4j.Logger logger = LoggerFactory.getLogger(PoorLoggingPracticeExamples.class);
        
        try {
            Storage storage = StorageOptions.getDefaultInstance().getService();
            
            // ok: java-poor-logging-practice
            logger.info("Listing GCS buckets");
            
            storage.list();
            
            // ok: java-poor-logging-practice
            logger.info("GCS buckets listed successfully");
        } catch (Exception e) {
            // ok: java-poor-logging-practice
            logger.error("Failed to list GCS buckets", e);
        }
    }
    
    public static void good_case_11() {
        // Azure Blob Storage with proper logging (Log4j2)
        org.apache.logging.log4j.Logger logger = LogManager.getLogger(PoorLoggingPracticeExamples.class);
        
        try {
            BlobServiceClient blobServiceClient = new BlobServiceClient.Builder()
                .connectionString("connection-string")
                .buildClient();
                
            // ok: java-poor-logging-practice
            logger.info("Listing Azure blob containers");
            
            blobServiceClient.listBlobContainers();
            
            // ok: java-poor-logging-practice
            logger.info("Azure blob containers listed successfully");
        } catch (Exception e) {
            // ok: java-poor-logging-practice
            logger.error("Failed to list Azure containers", e);
        }
    }
    
    @QuarkusMain
    public static class good_case_12 {
        // Quarkus application with proper logging
        private static final Logger logger = Logger.getLogger(good_case_12.class.getName());
        
        public static void main(String[] args) {
            // ok: java-poor-logging-practice
            logger.info("Starting Quarkus application");
            
            Quarkus.run(args);
            
            // ok: java-poor-logging-practice
            logger.info("Quarkus application started");
        }
    }
    
    public static void good_case_13(HttpServletRequest request) {
        // Play Framework with proper logging (SLF4J)
        org.slf4j.Logger logger = LoggerFactory.getLogger(PoorLoggingPracticeExamples.class);
        
        String path = request.getRequestURI();
        
        // ok: java-poor-logging-practice
        logger.info("Processing Play Framework request: {}", path);
        
        // Process request
        
        // ok: java-poor-logging-practice
        logger.info("Play Framework request processed: {}", path);
    }
    
    public static void good_case_14() {
        // Spark Java framework with proper logging (Log4j2)
        org.apache.logging.log4j.Logger logger = LogManager.getLogger(PoorLoggingPracticeExamples.class);
        
        Spark.get("/hello", (req, res) -> {
            String ip = req.ip();
            
            // ok: java-poor-logging-practice
            logger.info("Received request from IP: {}", ip);
            
            return "Hello World";
        });
        
        // ok: java-poor-logging-practice
        logger.info("Spark Java routes configured");
    }
    
    public static class good_case_15 implements RequestHandler<Object, String> {
        // AWS Lambda with proper logging
        private static final Logger logger = Logger.getLogger(good_case_15.class.getName());
        
        @Override
        public String handleRequest(Object input, Context context) {
            // ok: java-poor-logging-practice
            logger.info("Lambda function invoked with input: " + input);
            
            // Process the request
            
            // ok: java-poor-logging-practice
            logger.info("Lambda function execution completed");
            
            return "Success";
        }
    }
}
// {/fact}