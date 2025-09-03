import java.util.logging.Logger;
import java.util.logging.Level;
import org.apache.log4j.LogManager;
import org.slf4j.LoggerFactory;
import ch.qos.logback.classic.LoggerContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.compute.Compute;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ListBucketsRequest;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import java.util.Properties;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.core.http.HttpServerResponse;
import org.apache.commons.lang3.StringUtils;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.SQLException;
import io.quarkus.runtime.annotations.QuarkusMain;
import io.quarkus.runtime.Quarkus;
import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import org.jboss.logging.Logger;
import org.jboss.logging.Logger.Level;
import io.helidon.webserver.Routing;
import io.helidon.webserver.ServerRequest;
import io.helidon.webserver.ServerResponse;
import io.helidon.webserver.Service;
import io.helidon.webserver.WebServer;
import com.microsoft.azure.functions.*;
import com.microsoft.azure.functions.annotation.*;
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import com.sendgrid.*;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;
import org.apache.commons.codec.binary.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.text.StringSubstitutor;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

// Security Issue: Insecure Logging of Sensitive Information (CWE-532)

// True Positive Examples (Vulnerable/Insecure Code)

public class InsecureLoggingExamples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
// {fact rule=log-injection@v1.0 defects=1}
    public static void bad_case_1(HttpServletRequest request) {
        Logger logger = Logger.getLogger(InsecureLoggingExamples.class.getName());
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // ruleid: java-insecure-logging
        logger.info("User login attempt with username: " + username + " and password: " + password);
        
        // Process login
    }
    
    public static void bad_case_2() {
        org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(InsecureLoggingExamples.class);
        
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/auth")
            .header("Authorization", "Bearer secret_token_12345")
            .build();
            
        try {
            Response response = client.newCall(request).execute();
            // ruleid: java-insecure-logging
            logger.info("API call made with authorization token: Bearer secret_token_12345");
        } catch (IOException e) {
            logger.error("Error making API call", e);
        }
    }
    
    public static void bad_case_3() {
        org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(InsecureLoggingExamples.class);
        
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("https://api.example.com/data");
            String apiKey = "api_key_secret_7890";
            request.addHeader("X-API-Key", apiKey);
            
            // ruleid: java-insecure-logging
            logger.debug("Making API request with key: {}", apiKey);
            
            // Execute request
        } catch (Exception e) {
            logger.error("Error in API call", e);
        }
    }
    
    public static class bad_case_4 implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
        private static final org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(bad_case_4.class);
        
        @Override
        public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
            Map<String, String> headers = input.getHeaders();
            String authHeader = headers.get("Authorization");
            
            // ruleid: java-insecure-logging
            logger.info("Lambda function invoked with auth header: " + authHeader);
            
            // Process request
            return new APIGatewayProxyResponseEvent().withStatusCode(200);
        }
    }
    
    public static void bad_case_5() {
        Log log = LogFactory.getLog(InsecureLoggingExamples.class);
        
        try {
            Compute computeService = new Compute.Builder(
                new NetHttpTransport(),
                new JacksonFactory(),
                request -> request.getHeaders().set("Authorization", "Bearer gcp_secret_key_456")
            ).setApplicationName("MyApp").build();
            
            // ruleid: java-insecure-logging
            log.info("Initialized Google Compute Engine client with credentials: gcp_secret_key_456");
            
            // Use compute service
        } catch (Exception e) {
            log.error("Error initializing compute service", e);
        }
    }
    
    public static void bad_case_6() {
        Logger logger = Logger.getLogger(InsecureLoggingExamples.class.getName());
        
        String accessKey = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        S3Client s3 = S3Client.builder()
            .region(Region.US_WEST_2)
            .credentialsProvider(StaticCredentialsProvider.create(
                AwsBasicCredentials.create(accessKey, secretKey)))
            .build();
            
        // ruleid: java-insecure-logging
        logger.info("Created S3 client with access key: " + accessKey + " and secret key: " + secretKey);
        
        // Use S3 client
    }
    
    public static void bad_case_7() {
        org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(InsecureLoggingExamples.class);
        
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("sasl.jaas.config", "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"kafka_user\" password=\"kafka_secret_123\";");
        
        KafkaProducer<String, String> producer = new KafkaProducer<>(props);
        
        // ruleid: java-insecure-logging
        logger.log(org.jboss.logging.Logger.Level.INFO, "Kafka producer initialized with config: " + props.toString());
        
        // Use producer
    }
    
    @RestController
    public static class bad_case_8 {
        private final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(bad_case_8.class);
        
        @PostMapping("/payment")
        public String processPayment(@RequestBody Map<String, String> paymentInfo) {
            String cardNumber = paymentInfo.get("cardNumber");
            String cvv = paymentInfo.get("cvv");
            String expiry = paymentInfo.get("expiry");
            
            // ruleid: java-insecure-logging
            logger.info("Processing payment with card: {}, CVV: {}, Expiry: {}", cardNumber, cvv, expiry);
            
            // Process payment
            return "Payment processed";
        }
    }
    
    public static class bad_case_9 implements Service {
        private static final Logger LOGGER = Logger.getLogger(bad_case_9.class.getName());
        
        @Override
        public void update(Routing.Rules rules) {
            rules.get("/config", this::getConfig);
        }
        
        private void getConfig(ServerRequest request, ServerResponse response) {
            String authToken = request.headers().value("Authorization").orElse("");
            
            // ruleid: java-insecure-logging
            LOGGER.log(Level.INFO, "Helidon config request received with auth token: {0}", authToken);
            
            // Process request
            response.send("Config data");
        }
    }
    
    public static class bad_case_10 {
        private static final org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(bad_case_10.class);
        
        public void setupDatabase(HttpServletRequest request) {
            String jdbcUrl = request.getParameter("jdbcUrl");
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            
            HikariConfig config = new HikariConfig();
            config.setJdbcUrl(jdbcUrl);
            config.setUsername(username);
            config.setPassword(password);
            
            // ruleid: java-insecure-logging
            logger.info("Setting up database connection with URL: {}, username: {}, password: {}", 
                jdbcUrl, username, password);
            
            // Initialize connection pool
            HikariDataSource dataSource = new HikariDataSource(config);
        }
    }
    
    @RouteBase(path = "/api")
    public static class bad_case_11 {
        private static final org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(bad_case_11.class);
        
        @Route(path = "/login", methods = Route.HttpMethod.POST)
        public void login(io.vertx.ext.web.RoutingContext rc) {
            String username = rc.request().getParam("username");
            String password = rc.request().getParam("password");
            
            // ruleid: java-insecure-logging
            logger.info("Quarkus login attempt with username: " + username + " and password: " + password);
            
            // Process login
            rc.response().end("Login processed");
        }
    }
    
    @Controller("/api")
    public static class bad_case_12 {
        private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(bad_case_12.class);
        
        @Get("/user")
        public HttpResponse<String> getUser(HttpRequest<?> request) {
            String apiKey = request.getHeaders().get("X-API-Key");
            
            // ruleid: java-insecure-logging
            logger.info("Micronaut API request received with key: {}", apiKey);
            
            // Process request
            return HttpResponse.ok("User data");
        }
    }
    
    public static class bad_case_13 {
        private static final Logger logger = Logger.getLogger(bad_case_13.class.getName());
        
        @FunctionName("HttpTrigger")
        public HttpResponseMessage run(
                @HttpTrigger(name = "req", methods = {"post"}, authLevel = AuthorizationLevel.FUNCTION) 
                HttpRequestMessage<Optional<String>> request,
                final ExecutionContext context) {
            
            String body = request.getBody().orElse("");
            Map<String, String> credentials = new HashMap<>();
            credentials.put("username", request.getQueryParameters().get("username"));
            credentials.put("password", request.getQueryParameters().get("password"));
            
            // ruleid: java-insecure-logging
            logger.info("Azure function triggered with credentials: " + credentials);
            
            // Process request
            return request.createResponseBuilder(HttpStatus.OK).body("Function executed").build();
        }
    }
    
    public static void bad_case_14() {
        Logger logger = Logger.getLogger(InsecureLoggingExamples.class.getName());
        
        // Twilio API setup
        String accountSid = "AC_REDACTED_TWILIO_ID";
        String authToken = "auth_token_secret_987654";
        Twilio.init(accountSid, authToken);
        
        // ruleid: java-insecure-logging
        logger.info("Initialized Twilio client with SID: " + accountSid + " and auth token: " + authToken);
        
        // Send message
        Message message = Message.creator(
            new PhoneNumber("+15551234567"),
            new PhoneNumber("+15559876543"),
            "Hello from Twilio!"
        ).create();
    }
    
    public static void bad_case_15() {
        org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(InsecureLoggingExamples.class);
        
        // SendGrid API setup
        String apiKey = "SG.REDAC_REDACTED_TWILIO_ID_SENDGRID_KEY";
        SendGrid sendGrid = new SendGrid(apiKey);
        
        try {
            Email from = new Email("test@example.com");
            Email to = new Email("recipient@example.com");
            Content content = new Content("text/plain", "Hello, World!");
            Mail mail = new Mail(from, "Subject", to, content);
            
            Request request = new Request();
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            
            // ruleid: java-insecure-logging
            logger.info("Sending email via SendGrid with API key: {}", apiKey);
            
            // Send email
            Response response = sendGrid.api(request);
        } catch (IOException e) {
            logger.error("Error sending email", e);
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public static void good_case_1(HttpServletRequest request) {
        Logger logger = Logger.getLogger(InsecureLoggingExamples.class.getName());
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // ok: java-insecure-logging
        logger.info("User login attempt with username: " + username);
        
        // Process login
    }
    
    public static void good_case_2() {
        org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(InsecureLoggingExamples.class);
        
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/auth")
            .header("Authorization", "Bearer secret_token_12345")
            .build();
            
        try {
            Response response = client.newCall(request).execute();
            // ok: java-insecure-logging
            logger.info("API call made with authorization token: [REDAC_REDACTED_TWILIO_ID]");
        } catch (IOException e) {
            logger.error("Error making API call", e);
        }
    }
    
    public static void good_case_3() {
        org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(InsecureLoggingExamples.class);
        
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("https://api.example.com/data");
            String apiKey = "api_key_secret_7890";
            request.addHeader("X-API-Key", apiKey);
            
            // ok: java-insecure-logging
            logger.debug("Making API request with key: {}", maskSensitiveData(apiKey));
            
            // Execute request
        } catch (Exception e) {
            logger.error("Error in API call", e);
        }
    }
    
    private static String maskSensitiveData(String data) {
        if (data == null || data.length() < 4) {
            return "****";
        }
        return data.substring(0, 2) + "****" + data.substring(data.length() - 2);
    }
    
    public static class good_case_4 implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
        private static final org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(good_case_4.class);
        
        @Override
        public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
            Map<String, String> headers = input.getHeaders();
            String authHeader = headers.get("Authorization");
            
            // ok: java-insecure-logging
            logger.info("Lambda function invoked with auth header present: {}", authHeader != null ? "Yes" : "No");
            
            // Process request
            return new APIGatewayProxyResponseEvent().withStatusCode(200);
        }
    }
    
    public static void good_case_5() {
        Log log = LogFactory.getLog(InsecureLoggingExamples.class);
        
        try {
            final String gcpKey = "gcp_secret_key_456";
            Compute computeService = new Compute.Builder(
                new NetHttpTransport(),
                new JacksonFactory(),
                request -> request.getHeaders().set("Authorization", "Bearer " + gcpKey)
            ).setApplicationName("MyApp").build();
            
            // ok: java-insecure-logging
            log.info("Initialized Google Compute Engine client successfully");
            
            // Use compute service
        } catch (Exception e) {
            log.error("Error initializing compute service", e);
        }
    }
    
    public static void good_case_6() {
        Logger logger = Logger.getLogger(InsecureLoggingExamples.class.getName());
        
        String accessKey = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        
        S3Client s3 = S3Client.builder()
            .region(Region.US_WEST_2)
            .credentialsProvider(StaticCredentialsProvider.create(
                AwsBasicCredentials.create(accessKey, secretKey)))
            .build();
            
        // ok: java-insecure-logging
        logger.info("Created S3 client with access key ID: " + accessKey.substring(0, 5) + "...");
        
        // Use S3 client
    }
    
    public static void good_case_7() {
        org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(InsecureLoggingExamples.class);
        
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("sasl.jaas.config", "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"kafka_user\" password=\"kafka_secret_123\";");
        
        KafkaProducer<String, String> producer = new KafkaProducer<>(props);
        
        Properties safeProps = new Properties();
        safeProps.put("bootstrap.servers", props.getProperty("bootstrap.servers"));
        safeProps.put("sasl.jaas.config", "[REDAC_REDACTED_TWILIO_ID]");
        
        // ok: java-insecure-logging
        logger.log(org.jboss.logging.Logger.Level.INFO, "Kafka producer initialized with config: " + safeProps.toString());
        
        // Use producer
    }
    
    @RestController
    public static class good_case_8 {
        private final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(good_case_8.class);
        
        @PostMapping("/payment")
        public String processPayment(@RequestBody Map<String, String> paymentInfo) {
            String cardNumber = paymentInfo.get("cardNumber");
            String cvv = paymentInfo.get("cvv");
            String expiry = paymentInfo.get("expiry");
            
            String maskedCardNumber = maskCardNumber(cardNumber);
            
            // ok: java-insecure-logging
            logger.info("Processing payment with card: {}, Expiry: {}", maskedCardNumber, expiry);
            
            // Process payment
            return "Payment processed";
        }
        
        private String maskCardNumber(String cardNumber) {
            if (cardNumber == null || cardNumber.length() < 4) {
                return "****";
            }
            return "****-****-****-" + cardNumber.substring(cardNumber.length() - 4);
        }
    }
    
    public static class good_case_9 implements Service {
        private static final Logger LOGGER = Logger.getLogger(good_case_9.class.getName());
        
        @Override
        public void update(Routing.Rules rules) {
            rules.get("/config", this::getConfig);
        }
        
        private void getConfig(ServerRequest request, ServerResponse response) {
            boolean hasAuthToken = request.headers().value("Authorization").isPresent();
            
            // ok: java-insecure-logging
            LOGGER.log(Level.INFO, "Helidon config request received with auth token present: {0}", hasAuthToken);
            
            // Process request
            response.send("Config data");
        }
    }
    
    public static class good_case_10 {
        private static final org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(good_case_10.class);
        
        public void setupDatabase(HttpServletRequest request) {
            String jdbcUrl = request.getParameter("jdbcUrl");
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            
            HikariConfig config = new HikariConfig();
            config.setJdbcUrl(jdbcUrl);
            config.setUsername(username);
            config.setPassword(password);
            
            // ok: java-insecure-logging
            logger.info("Setting up database connection with URL: {}, username: {}", 
                jdbcUrl, username);
            
            // Initialize connection pool
            HikariDataSource dataSource = new HikariDataSource(config);
        }
    }
    
    @RouteBase(path = "/api")
    public static class good_case_11 {
        private static final org.jboss.logging.Logger logger = org.jboss.logging.Logger.getLogger(good_case_11.class);
        
        @Route(path = "/login", methods = Route.HttpMethod.POST)
        public void login(io.vertx.ext.web.RoutingContext rc) {
            String username = rc.request().getParam("username");
            String password = rc.request().getParam("password");
            
            // ok: java-insecure-logging
            logger.info("Quarkus login attempt for user: " + username);
            
            // Process login
            rc.response().end("Login processed");
        }
    }
    
    @Controller("/api")
    public static class good_case_12 {
        private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(good_case_12.class);
        
        @Get("/user")
        public HttpResponse<String> getUser(HttpRequest<?> request) {
            String apiKey = request.getHeaders().get("X-API-Key");
            boolean hasApiKey = apiKey != null && !apiKey.isEmpty();
            
            // ok: java-insecure-logging
            logger.info("Micronaut API request received with API key present: {}", hasApiKey);
            
            // Process request
            return HttpResponse.ok("User data");
        }
    }
    
    public static class good_case_13 {
        private static final Logger logger = Logger.getLogger(good_case_13.class.getName());
        
        @FunctionName("HttpTrigger")
        public HttpResponseMessage run(
                @HttpTrigger(name = "req", methods = {"post"}, authLevel = AuthorizationLevel.FUNCTION) 
                HttpRequestMessage<Optional<String>> request,
                final ExecutionContext context) {
            
            String body = request.getBody().orElse("");
            String username = request.getQueryParameters().get("username");
            
            // ok: java-insecure-logging
            logger.info("Azure function triggered for user: " + username);
            
            // Process request
            return request.createResponseBuilder(HttpStatus.OK).body("Function executed").build();
        }
    }
    
    public static void good_case_14() {
        Logger logger = Logger.getLogger(InsecureLoggingExamples.class.getName());
        
        // Twilio API setup
        String accountSid = "AC_REDACTED_TWILIO_ID";
        String authToken = "auth_token_secret_987654";
        Twilio.init(accountSid, authToken);
        
        // ok: java-insecure-logging
        logger.info("Initialized Twilio client with SID: " + accountSid);
        
        // Send message
        Message message = Message.creator(
            new PhoneNumber("+15551234567"),
            new PhoneNumber("+15559876543"),
            "Hello from Twilio!"
        ).create();
    }
    
    public static void good_case_15() {
        org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(InsecureLoggingExamples.class);
        
        // SendGrid API setup
        String apiKey = "SG.REDAC_REDACTED_TWILIO_ID_SENDGRID_KEY";
        SendGrid sendGrid = new SendGrid(apiKey);
        
        try {
            Email from = new Email("test@example.com");
            Email to = new Email("recipient@example.com");
            Content content = new Content("text/plain", "Hello, World!");
            Mail mail = new Mail(from, "Subject", to, content);
            
            Request request = new Request();
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            
            // ok: java-insecure-logging
            logger.info("Sending email via SendGrid");
            
            // Send email
            Response response = sendGrid.api(request);
        } catch (IOException e) {
            logger.error("Error sending email", e);
        }
    }
}
// {/fact}