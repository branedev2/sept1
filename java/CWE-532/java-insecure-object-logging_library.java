import java.util.logging.Logger;
import java.util.logging.Level;
import org.slf4j.LoggerFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.core.ConsoleAppender;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Retrofit;
import retrofit2.Call;
import retrofit2.http.GET;
import retrofit2.http.Path;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.azure.core.http.rest.Response;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpEntity;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.URI;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;
import org.asynchttpclient.Response;
import feign.Feign;
import feign.RequestLine;
import feign.jackson.JacksonDecoder;
import kong.unirest.JsonNode;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;

// Security Issue: Insecure Object Logging - Logging entire objects without proper sanitization can expose sensitive information

// True Positive Examples (Vulnerable/Insecure Code)
class UserCredentials {
    private String username;
    private String password;
    
    public UserCredentials(String username, String password) {
        this.username = username;
        this.password = password;
    }
    
    // Getters and setters
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public void setUsername(String username) { this.username = username; }
    public void setPassword(String password) { this.password = password; }
}

// 1. Java Util Logging (JUL)
public void bad_case_1(HttpServletRequest request) {
    Logger logger = Logger.getLogger(getClass().getName());
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    
    UserCredentials credentials = new UserCredentials(username, password);
    
    // ruleid: java-insecure-object-logging
    logger.info("User credentials: " + credentials);
}

// 2. SLF4J with Logback
public void bad_case_2(HttpServletRequest request) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    
    Map<String, String> userInfo = new HashMap<>();
    userInfo.put("username", request.getParameter("username"));
    userInfo.put("password", request.getParameter("password"));
    userInfo.put("token", request.getHeader("Authorization"));
    
    // ruleid: java-insecure-object-logging
    logger.info("Processing user information: {}", userInfo);
}

// 3. Log4j2
public void bad_case_3(HttpServletRequest request) {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    
    class PaymentDetails {
        String cardNumber;
        String cvv;
        String expiry;
        
        public PaymentDetails(String cardNumber, String cvv, String expiry) {
            this.cardNumber = cardNumber;
            this.cvv = cvv;
            this.expiry = expiry;
        }
    }
    
    PaymentDetails payment = new PaymentDetails(
        request.getParameter("cardNumber"),
        request.getParameter("cvv"),
        request.getParameter("expiry")
    );
    
    // ruleid: java-insecure-object-logging
    logger.info("Payment processed: {}", payment);
}

// 4. Apache Commons Logging
public void bad_case_4(HttpServletRequest request) {
    Log log = LogFactory.getLog(getClass());
    
    class SessionData {
        String sessionId;
        String userToken;
        Map<String, String> userData;
        
        public SessionData(String sessionId, String userToken, Map<String, String> userData) {
            this.sessionId = sessionId;
            this.userToken = userToken;
            this.userData = userData;
        }
    }
    
    Map<String, String> userData = new HashMap<>();
    userData.put("ssn", request.getParameter("ssn"));
    userData.put("dob", request.getParameter("dob"));
    
    SessionData session = new SessionData(
        request.getSession().getId(),
        request.getHeader("X-Auth-Token"),
        userData
    );
    
    // ruleid: java-insecure-object-logging
    log.info("User session: " + session);
}

// 5. Spring Boot RestTemplate
@RestController
public class bad_case_5 {
    private final Logger logger = Logger.getLogger(getClass().getName());
    
    @GetMapping("/api/user/{id}")
    public String getUserData(@PathVariable String id, @RequestHeader HttpHeaders headers) {
        RestTemplate restTemplate = new RestTemplateBuilder().build();
        
        ResponseEntity<UserCredentials> response = restTemplate.getForEntity(
            "https://api.example.com/users/" + id, 
            UserCredentials.class
        );
        
        UserCredentials userData = response.getBody();
        
        // ruleid: java-insecure-object-logging
        logger.info("Retrieved user data: " + userData);
        
        return "User data retrieved";
    }
}

// 6. OkHttp Client
public void bad_case_6(HttpServletRequest request) {
    Logger logger = Logger.getLogger(getClass().getName());
    String apiKey = request.getHeader("X-API-Key");
    
    class ApiResponse {
        String token;
        String refreshToken;
        Map<String, Object> userData;
        
        @Override
        public String toString() {
            return "ApiResponse{token='" + token + "', refreshToken='" + refreshToken + "', userData=" + userData + '}';
        }
    }
    
    try {
        OkHttpClient client = new OkHttpClient();
        Request okRequest = new Request.Builder()
            .url("https://api.example.com/auth")
            .header("Authorization", "Bearer " + apiKey)
            .build();
            
        try (okhttp3.Response response = client.newCall(okRequest).execute()) {
            ObjectMapper mapper = new ObjectMapper();
            ApiResponse apiResponse = mapper.readValue(response.body().string(), ApiResponse.class);
            
            // ruleid: java-insecure-object-logging
            logger.info("API authentication response: " + apiResponse);
        }
    } catch (Exception e) {
        logger.severe("Error: " + e.getMessage());
    }
}

// 7. AWS SDK
public void bad_case_7(HttpServletRequest request) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    
    class AwsSecretData {
        Map<String, String> secretData;
        String secretArn;
        
        public AwsSecretData(Map<String, String> secretData, String secretArn) {
            this.secretData = secretData;
            this.secretArn = secretArn;
        }
    }
    
    String secretName = request.getParameter("secretName");
    
    try {
        software.amazon.awssdk.services.secretsmanager.SecretsManagerClient client = 
            software.amazon.awssdk.services.secretsmanager.SecretsManagerClient.create();
            
        software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest getSecretValueRequest = 
            software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest.builder()
                .secretId(secretName)
                .build();
                
        software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse response = 
            client.getSecretValue(getSecretValueRequest);
            
        Map<String, String> secretData = new HashMap<>();
        secretData.put("secretString", response.secretString());
        
        AwsSecretData awsSecretData = new AwsSecretData(secretData, response.arn());
        
        // ruleid: java-insecure-object-logging
        logger.info("Retrieved AWS secret: {}", awsSecretData);
    } catch (Exception e) {
        logger.error("Error retrieving secret", e);
    }
}

// 8. Retrofit API Client
public void bad_case_8(HttpServletRequest request) {
    Logger logger = Logger.getLogger(getClass().getName());
    
    interface GitHubService {
        @GET("users/{user}/repos")
        Call<Object> listRepos(@Path("user") String user);
    }
    
    String username = request.getParameter("username");
    String token = request.getHeader("Authorization");
    
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl("https://api.github.com/")
        .addConverterFactory(retrofit2.converter.jackson.JacksonConverterFactory.create())
        .build();
        
    GitHubService service = retrofit.create(GitHubService.class);
    
    try {
        Object repos = service.listRepos(username).execute().body();
        
        // ruleid: java-insecure-object-logging
        logger.info("GitHub repositories with auth token " + token + ": " + repos);
    } catch (Exception e) {
        logger.severe("Error: " + e.getMessage());
    }
}

// 9. Google Cloud Functions
public class bad_case_9 implements HttpFunction {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(bad_case_9.class);
    
    @Override
    public void service(com.google.cloud.functions.HttpRequest request, com.google.cloud.functions.HttpResponse response) throws Exception {
        class UserProfile {
            String name;
            String email;
            String socialSecurityNumber;
            
            public UserProfile(String name, String email, String ssn) {
                this.name = name;
                this.email = email;
                this.socialSecurityNumber = ssn;
            }
        }
        
        String name = request.getFirstQueryParameter("name").orElse("");
        String email = request.getFirstQueryParameter("email").orElse("");
        String ssn = request.getFirstQueryParameter("ssn").orElse("");
        
        UserProfile profile = new UserProfile(name, email, ssn);
        
        // ruleid: java-insecure-object-logging
        logger.info("Processing user profile: {}", profile);
        
        response.getWriter().write("Profile processed");
    }
}

// 10. Vert.x Web Framework
public void bad_case_10() {
    Logger logger = Logger.getLogger(getClass().getName());
    
    Vertx vertx = Vertx.vertx();
    Router router = Router.router(vertx);
    
    router.get("/api/payment").handler(ctx -> {
        class PaymentInfo {
            String cardNumber;
            String cardholderName;
            String cvv;
            
            public PaymentInfo(String cardNumber, String cardholderName, String cvv) {
                this.cardNumber = cardNumber;
                this.cardholderName = cardholderName;
                this.cvv = cvv;
            }
        }
        
        String cardNumber = ctx.request().getParam("cardNumber");
        String cardholderName = ctx.request().getParam("cardholderName");
        String cvv = ctx.request().getParam("cvv");
        
        PaymentInfo paymentInfo = new PaymentInfo(cardNumber, cardholderName, cvv);
        
        // ruleid: java-insecure-object-logging
        logger.info("Processing payment: " + paymentInfo);
        
        ctx.response().end("Payment processed");
    });
    
    vertx.createHttpServer().requestHandler(router).listen(8080);
}

// 11. Micronaut Framework
@Controller("/api")
public class bad_case_11 {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(bad_case_11.class);
    
    @Get("/login")
    public String login(io.micronaut.http.HttpRequest<?> request) {
        class LoginRequest {
            String username;
            String password;
            String clientId;
            
            public LoginRequest(String username, String password, String clientId) {
                this.username = username;
                this.password = password;
                this.clientId = clientId;
            }
        }
        
        String username = request.getParameters().get("username");
        String password = request.getParameters().get("password");
        String clientId = request.getParameters().get("clientId");
        
        LoginRequest loginRequest = new LoginRequest(username, password, clientId);
        
        // ruleid: java-insecure-object-logging
        logger.info("Login attempt: {}", loginRequest);
        
        return "Login processed";
    }
}

// 12. Javalin Framework
public void bad_case_12() {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    
    Javalin app = Javalin.create().start(7000);
    
    app.post("/api/register", ctx -> {
        class RegistrationData {
            String username;
            String password;
            String email;
            String phoneNumber;
            
            public RegistrationData(String username, String password, String email, String phoneNumber) {
                this.username = username;
                this.password = password;
                this.email = email;
                this.phoneNumber = phoneNumber;
            }
        }
        
        RegistrationData regData = new RegistrationData(
            ctx.formParam("username"),
            ctx.formParam("password"),
            ctx.formParam("email"),
            ctx.formParam("phoneNumber")
        );
        
        // ruleid: java-insecure-object-logging
        logger.info("User registration: {}", regData);
        
        ctx.result("Registration successful");
    });
}

// 13. Azure SDK
public void bad_case_13(HttpServletRequest request) {
    Logger logger = Logger.getLogger(getClass().getName());
    
    String keyVaultName = request.getParameter("keyVaultName");
    String secretName = request.getParameter("secretName");
    
    class AzureSecretInfo {
        String name;
        String value;
        String id;
        
        public AzureSecretInfo(String name, String value, String id) {
            this.name = name;
            this.value = value;
            this.id = id;
        }
    }
    
    try {
        SecretClient secretClient = new SecretClientBuilder()
            .vaultUrl("https://" + keyVaultName + ".vault.azure.net")
            .credential(new DefaultAzureCredentialBuilder().build())
            .buildClient();
            
        KeyVaultSecret secret = secretClient.getSecret(secretName);
        AzureSecretInfo secretInfo = new AzureSecretInfo(secret.getName(), secret.getValue(), secret.getId());
        
        // ruleid: java-insecure-object-logging
        logger.info("Retrieved Azure secret: " + secretInfo);
    } catch (Exception e) {
        logger.severe("Error retrieving Azure secret: " + e.getMessage());
    }
}

// 14. Google API Client
public void bad_case_14(HttpServletRequest request) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    
    String userId = request.getParameter("userId");
    
    class GoogleUserData {
        Map<String, Object> userData;
        String accessToken;
        
        public GoogleUserData(Map<String, Object> userData, String accessToken) {
            this.userData = userData;
            this.accessToken = accessToken;
        }
    }
    
    try {
        HttpRequestFactory requestFactory = new NetHttpTransport()
            .createRequestFactory(request1 -> request1.setParser(new JsonObjectParser(new JacksonFactory())));
            
        com.google.api.client.http.HttpRequest googleRequest = requestFactory.buildGetRequest(
            new GenericUrl("https://www.googleapis.com/oauth2/v3/userinfo?userId=" + userId));
            
        googleRequest.getHeaders().set("Authorization", "Bearer " + request.getHeader("X-Google-Token"));
        
        com.google.api.client.http.HttpResponse googleResponse = googleRequest.execute();
        Map<String, Object> userData = googleResponse.parseAs(Map.class);
        
        GoogleUserData googleUserData = new GoogleUserData(userData, request.getHeader("X-Google-Token"));
        
        // ruleid: java-insecure-object-logging
        logger.info("Google user data: {}", googleUserData);
    } catch (Exception e) {
        logger.error("Error fetching Google user data", e);
    }
}

// 15. Spring OAuth2 Client
public void bad_case_15(HttpServletRequest request, OAuth2AuthorizedClientService clientService) {
    Logger logger = Logger.getLogger(getClass().getName());
    
    String username = request.getParameter("username");
    
    class OAuth2UserInfo {
        UserDetails userDetails;
        OAuth2AccessToken accessToken;
        
        public OAuth2UserInfo(UserDetails userDetails, OAuth2AccessToken accessToken) {
            this.userDetails = userDetails;
            this.accessToken = accessToken;
        }
    }
    
    try {
        UserDetails userDetails = User.withUsername(username)
            .password("tempPassword")
            .roles("USER")
            .build();
            
        OAuth2AuthorizedClient authorizedClient = clientService.loadAuthorizedClient(
            "client-registration-id", username);
            
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        
        OAuth2UserInfo userInfo = new OAuth2UserInfo(userDetails, accessToken);
        
        // ruleid: java-insecure-object-logging
        logger.info("OAuth2 user information: " + userInfo);
    } catch (Exception e) {
        logger.severe("Error processing OAuth2 user: " + e.getMessage());
    }
}

// True Negative Examples (Safe/Secure Code)

// 1. Java Util Logging (JUL) - Safe Version
public void good_case_1(HttpServletRequest request) {
    Logger logger = Logger.getLogger(getClass().getName());
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    
    UserCredentials credentials = new UserCredentials(username, password);
    
    // ok: java-insecure-object-logging
    logger.info("User logged in: " + credentials.getUsername() + ", password length: " + (password != null ? "****" : "null"));
}

// 2. SLF4J with Logback - Safe Version
public void good_case_2(HttpServletRequest request) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    
    Map<String, String> userInfo = new HashMap<>();
    userInfo.put("username", request.getParameter("username"));
    userInfo.put("password", "********");
    userInfo.put("token", "********");
    
    Map<String, String> safeUserInfo = new HashMap<>();
    safeUserInfo.put("username", userInfo.get("username"));
    
    // ok: java-insecure-object-logging
    logger.info("Processing user information: {}", safeUserInfo);
}

// 3. Log4j2 - Safe Version
public void good_case_3(HttpServletRequest request) {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    
    class PaymentDetails {
        String cardNumber;
        String cvv;
        String expiry;
        
        public PaymentDetails(String cardNumber, String cvv, String expiry) {
            this.cardNumber = cardNumber;
            this.cvv = cvv;
            this.expiry = expiry;
        }
        
        public String getSafeCardNumber() {
            if (cardNumber == null || cardNumber.length() < 4) {
                return "****";
            }
            return "****" + cardNumber.substring(cardNumber.length() - 4);
        }
    }
    
    PaymentDetails payment = new PaymentDetails(
        request.getParameter("cardNumber"),
        request.getParameter("cvv"),
        request.getParameter("expiry")
    );
    
    // ok: java-insecure-object-logging
    logger.info("Payment processed with card ending in: {}", payment.getSafeCardNumber());
}

// 4. Apache Commons Logging - Safe Version
public void good_case_4(HttpServletRequest request) {
    Log log = LogFactory.getLog(getClass());
    
    class SessionData {
        String sessionId;
        String userToken;
        Map<String, String> userData;
        
        public SessionData(String sessionId, String userToken, Map<String, String> userData) {
            this.sessionId = sessionId;
            this.userToken = userToken;
            this.userData = userData;
        }
        
        public String getSafeSessionInfo() {
            return "SessionData{sessionId='" + sessionId + "', userAuthenticated=" + (userToken != null) + "}";
        }
    }
    
    Map<String, String> userData = new HashMap<>();
    userData.put("ssn", request.getParameter("ssn"));
    userData.put("dob", request.getParameter("dob"));
    
    SessionData session = new SessionData(
        request.getSession().getId(),
        request.getHeader("X-Auth-Token"),
        userData
    );
    
    // ok: java-insecure-object-logging
    log.info("User session: " + session.getSafeSessionInfo());
}

// 5. Spring Boot RestTemplate - Safe Version
@RestController
public class good_case_5 {
    private final Logger logger = Logger.getLogger(getClass().getName());
    
    @GetMapping("/api/user/{id}")
    public String getUserData(@PathVariable String id, @RequestHeader HttpHeaders headers) {
        RestTemplate restTemplate = new RestTemplateBuilder().build();
        
        ResponseEntity<UserCredentials> response = restTemplate.getForEntity(
            "https://api.example.com/users/" + id, 
            UserCredentials.class
        );
        
        UserCredentials userData = response.getBody();
        
        // ok: java-insecure-object-logging
        logger.info("Retrieved user data for: " + (userData != null ? userData.getUsername() : "unknown"));
        
        return "User data retrieved";
    }
}

// 6. OkHttp Client - Safe Version
public void good_case_6(HttpServletRequest request) {
    Logger logger = Logger.getLogger(getClass().getName());
    String apiKey = request.getHeader("X-API-Key");
    
    class ApiResponse {
        String token;
        String refreshToken;
        Map<String, Object> userData;
        
        public String getSafeInfo() {
            return "ApiResponse{tokenPresent=" + (token != null) + 
                   ", refreshTokenPresent=" + (refreshToken != null) + 
                   ", userDataFields=" + (userData != null ? userData.keySet() : "null") + "}";
        }
    }
    
    try {
        OkHttpClient client = new OkHttpClient();
        Request okRequest = new Request.Builder()
            .url("https://api.example.com/auth")
            .header("Authorization", "Bearer " + apiKey)
            .build();
            
        try (okhttp3.Response response = client.newCall(okRequest).execute()) {
            ObjectMapper mapper = new ObjectMapper();
            ApiResponse apiResponse = mapper.readValue(response.body().string(), ApiResponse.class);
            
            // ok: java-insecure-object-logging
            logger.info("API authentication response: " + apiResponse.getSafeInfo());
        }
    } catch (Exception e) {
        logger.severe("Error: " + e.getMessage());
    }
}

// 7. AWS SDK - Safe Version
public void good_case_7(HttpServletRequest request) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    
    class AwsSecretData {
        Map<String, String> secretData;
        String secretArn;
        
        public AwsSecretData(Map<String, String> secretData, String secretArn) {
            this.secretData = secretData;
            this.secretArn = secretArn;
        }
        
        public String getSafeInfo() {
            return "AwsSecretData{secretArn='" + secretArn + 
                   "', secretDataPresent=" + (secretData != null && !secretData.isEmpty()) + "}";
        }
    }
    
    String secretName = request.getParameter("secretName");
    
    try {
        software.amazon.awssdk.services.secretsmanager.SecretsManagerClient client = 
            software.amazon.awssdk.services.secretsmanager.SecretsManagerClient.create();
            
        software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest getSecretValueRequest = 
            software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest.builder()
                .secretId(secretName)
                .build();
                
        software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse response = 
            client.getSecretValue(getSecretValueRequest);
            
        Map<String, String> secretData = new HashMap<>();
        secretData.put("secretString", response.secretString());
        
        AwsSecretData awsSecretData = new AwsSecretData(secretData, response.arn());
        
        // ok: java-insecure-object-logging
        logger.info("Retrieved AWS secret: {}", awsSecretData.getSafeInfo());
    } catch (Exception e) {
        logger.error("Error retrieving secret", e);
    }
}

// 8. Retrofit API Client - Safe Version
public void good_case_8(HttpServletRequest request) {
    Logger logger = Logger.getLogger(getClass().getName());
    
    interface GitHubService {
        @GET("users/{user}/repos")
        Call<Object> listRepos(@Path("user") String user);
    }
    
    String username = request.getParameter("username");
    String token = request.getHeader("Authorization");
    
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl("https://api.github.com/")
        .addConverterFactory(retrofit2.converter.jackson.JacksonConverterFactory.create())
        .build();
        
    GitHubService service = retrofit.create(GitHubService.class);
    
    try {
        Object repos = service.listRepos(username).execute().body();
        
        // ok: java-insecure-object-logging
        logger.info("GitHub repositories fetched for user: " + username + ", auth: " + 
                   (token != null ? "[REDAC_REDACTED_TWILIO_ID]" : "none"));
    } catch (Exception e) {
        logger.severe("Error: " + e.getMessage());
    }
}

// 9. Google Cloud Functions - Safe Version
public class good_case_9 implements HttpFunction {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(good_case_9.class);
    
    @Override
    public void service(com.google.cloud.functions.HttpRequest request, com.google.cloud.functions.HttpResponse response) throws Exception {
        class UserProfile {
            String name;
            String email;
            String socialSecurityNumber;
            
            public UserProfile(String name, String email, String ssn) {
                this.name = name;
                this.email = email;
                this.socialSecurityNumber = ssn;
            }
            
            public String getSafeInfo() {
                return "UserProfile{name='" + name + "', email='" + email + "', ssnPresent=" + 
                       (socialSecurityNumber != null && !socialSecurityNumber.isEmpty()) + "}";
            }
        }
        
        String name = request.getFirstQueryParameter("name").orElse("");
        String email = request.getFirstQueryParameter("email").orElse("");
        String ssn = request.getFirstQueryParameter("ssn").orElse("");
        
        UserProfile profile = new UserProfile(name, email, ssn);
        
        // ok: java-insecure-object-logging
        logger.info("Processing user profile: {}", profile.getSafeInfo());
        
        response.getWriter().write("Profile processed");
    }
}

// 10. Vert.x Web Framework - Safe Version
public void good_case_10() {
    Logger logger = Logger.getLogger(getClass().getName());
    
    Vertx vertx = Vertx.vertx();
    Router router = Router.router(vertx);
    
    router.get("/api/payment").handler(ctx -> {
        class PaymentInfo {
            String cardNumber;
            String cardholderName;
            String cvv;
            
            public PaymentInfo(String cardNumber, String cardholderName, String cvv) {
                this.cardNumber = cardNumber;
                this.cardholderName = cardholderName;
                this.cvv = cvv;
            }
            
            public String getSafeInfo() {
                String maskedCardNumber = null;
                if (cardNumber != null && cardNumber.length() > 4) {
                    maskedCardNumber = "****" + cardNumber.substring(cardNumber.length() - 4);
                } else {
                    maskedCardNumber = "****";
                }
                
                return "PaymentInfo{cardNumber='" + maskedCardNumber + 
                       "', cardholderName='" + cardholderName + "', cvvPresent=" + (cvv != null) + "}";
            }
        }
        
        String cardNumber = ctx.request().getParam("cardNumber");
        String cardholderName = ctx.request().getParam("cardholderName");
        String cvv = ctx.request().getParam("cvv");
        
        PaymentInfo paymentInfo = new PaymentInfo(cardNumber, cardholderName, cvv);
        
        // ok: java-insecure-object-logging
        logger.info("Processing payment: " + paymentInfo.getSafeInfo());
        
        ctx.response().end("Payment processed");
    });
    
    vertx.createHttpServer().requestHandler(router).listen(8080);
}

// 11. Micronaut Framework - Safe Version
@Controller("/api")
public class good_case_11 {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(good_case_11.class);
    
    @Get("/login")
    public String login(io.micronaut.http.HttpRequest<?> request) {
        class LoginRequest {
            String username;
            String password;
            String clientId;
            
            public LoginRequest(String username, String password, String clientId) {
                this.username = username;
                this.password = password;
                this.clientId = clientId;
            }
            
            public String getSafeInfo() {
                return "LoginRequest{username='" + username + 
                       "', passwordPresent=" + (password != null && !password.isEmpty()) + 
                       ", clientId='" + clientId + "'}";
            }
        }
        
        String username = request.getParameters().get("username");
        String password = request.getParameters().get("password");
        String clientId = request.getParameters().get("clientId");
        
        LoginRequest loginRequest = new LoginRequest(username, password, clientId);
        
        // ok: java-insecure-object-logging
        logger.info("Login attempt: {}", loginRequest.getSafeInfo());
        
        return "Login processed";
    }
}

// 12. Javalin Framework - Safe Version
public void good_case_12() {
    org.apache.logging.log4j.Logger logger = LogManager.getLogger(getClass());
    
    Javalin app = Javalin.create().start(7000);
    
    app.post("/api/register", ctx -> {
        class RegistrationData {
            String username;
            String password;
            String email;
            String phoneNumber;
            
            public RegistrationData(String username, String password, String email, String phoneNumber) {
                this.username = username;
                this.password = password;
                this.email = email;
                this.phoneNumber = phoneNumber;
            }
            
            public Map<String, Object> getSafeData() {
                Map<String, Object> safeData = new HashMap<>();
                safeData.put("username", username);
                safeData.put("email", email);
                safeData.put("phoneNumberProvided", phoneNumber != null && !phoneNumber.isEmpty());
                return safeData;
            }
        }
        
        RegistrationData regData = new RegistrationData(
            ctx.formParam("username"),
            ctx.formParam("password"),
            ctx.formParam("email"),
            ctx.formParam("phoneNumber")
        );
        
        // ok: java-insecure-object-logging
        logger.info("User registration: {}", regData.getSafeData());
        
        ctx.result("Registration successful");
    });
}

// 13. Azure SDK - Safe Version
public void good_case_13(HttpServletRequest request) {
    Logger logger = Logger.getLogger(getClass().getName());
    
    String keyVaultName = request.getParameter("keyVaultName");
    String secretName = request.getParameter("secretName");
    
    class AzureSecretInfo {
        String name;
        String value;
        String id;
        
        public AzureSecretInfo(String name, String value, String id) {
            this.name = name;
            this.value = value;
            this.id = id;
        }
        
        public String getSafeInfo() {
            return "AzureSecretInfo{name='" + name + "', id='" + id + "'}";
        }
    }
    
    try {
        SecretClient secretClient = new SecretClientBuilder()
            .vaultUrl("https://" + keyVaultName + ".vault.azure.net")
            .credential(new DefaultAzureCredentialBuilder().build())
            .buildClient();
            
        KeyVaultSecret secret = secretClient.getSecret(secretName);
        AzureSecretInfo secretInfo = new AzureSecretInfo(secret.getName(), secret.getValue(), secret.getId());
        
        // ok: java-insecure-object-logging
        logger.info("Retrieved Azure secret: " + secretInfo.getSafeInfo());
    } catch (Exception e) {
        logger.severe("Error retrieving Azure secret: " + e.getMessage());
    }
}

// 14. Google API Client - Safe Version
public void good_case_14(HttpServletRequest request) {
    org.slf4j.Logger logger = LoggerFactory.getLogger(getClass());
    
    String userId = request.getParameter("userId");
    
    class GoogleUserData {
        Map<String, Object> userData;
        String accessToken;
        
        public GoogleUserData(Map<String, Object> userData, String accessToken) {
            this.userData = userData;
            this.accessToken = accessToken;
        }
        
        public Map<String, Object> getSafeData() {
            Map<String, Object> safeData = new HashMap<>();
            if (userData != null) {
                if (userData.containsKey("name")) safeData.put("name", userData.get("name"));
                if (userData.containsKey("email")) safeData.put("email", userData.get("email"));
                safeData.put("hasAccessToken", accessToken != null && !accessToken.isEmpty());
            }
            return safeData;
        }
    }
    
    try {
        HttpRequestFactory requestFactory = new NetHttpTransport()
            .createRequestFactory(request1 -> request1.setParser(new JsonObjectParser(new JacksonFactory())));
            
        com.google.api.client.http.HttpRequest googleRequest = requestFactory.buildGetRequest(
            new GenericUrl("https://www.googleapis.com/oauth2/v3/userinfo?userId=" + userId));
            
        googleRequest.getHeaders().set("Authorization", "Bearer " + request.getHeader("X-Google-Token"));
        
        com.google.api.client.http.HttpResponse googleResponse = googleRequest.execute();
        Map<String, Object> userData = googleResponse.parseAs(Map.class);
        
        GoogleUserData googleUserData = new GoogleUserData(userData, request.getHeader("X-Google-Token"));
        
        // ok: java-insecure-object-logging
        logger.info("Google user data: {}", googleUserData.getSafeData());
    } catch (Exception e) {
        logger.error("Error fetching Google user data", e);
    }
}

// 15. Spring OAuth2 Client - Safe Version
public void good_case_15(HttpServletRequest request, OAuth2AuthorizedClientService clientService) {
    Logger logger = Logger.getLogger(getClass().getName());
    
    String username = request.getParameter("username");
    
    class OAuth2UserInfo {
        UserDetails userDetails;
        OAuth2AccessToken accessToken;
        
        public OAuth2UserInfo(UserDetails userDetails, OAuth2AccessToken accessToken) {
            this.userDetails = userDetails;
            this.accessToken = accessToken;
        }
        
        public String getSafeInfo() {
            return "OAuth2UserInfo{username='" + (userDetails != null ? userDetails.getUsername() : "null") + 
                   "', authorities=" + (userDetails != null ? userDetails.getAuthorities() : "null") + 
                   ", tokenExpiry=" + (accessToken != null ? accessToken.getExpiresAt() : "null") + "}";
        }
    }
    
    try {
        UserDetails userDetails = User.withUsername(username)
            .password("tempPassword")
            .roles("USER")
            .build();
            
        OAuth2AuthorizedClient authorizedClient = clientService.loadAuthorizedClient(
            "client-registration-id", username);
            
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        
        OAuth2UserInfo userInfo = new OAuth2UserInfo(userDetails, accessToken);
        
        // ok: java-insecure-object-logging
        logger.info("OAuth2 user information: " + userInfo.getSafeInfo());
    } catch (Exception e) {
        logger.severe("Error processing OAuth2 user: " + e.getMessage());
    }
}