import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.stereotype.Controller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
public class ObjectMapperExceptionHandlingExamples {
    
    private static final Logger logger = LoggerFactory.getLogger(ObjectMapperExceptionHandlingExamples.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    // True Positive Examples (Vulnerable Code)
    
// {fact rule=unhandled-exceptions@v1.0 defects=1}
    @PostMapping("/bad_case_1")
    public String bad_case_1(@RequestBody String jsonInput) {
        User user = null;
        try {
            user = objectMapper.readValue(jsonInput, User.class);
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            // Empty catch block swallows the exception
        }
        return "Processed user: " + (user != null ? user.getName() : "unknown");
    }
    
    @PostMapping("/bad_case_2")
    public Map<String, Object> bad_case_2(@RequestBody String jsonData) {
        Map<String, Object> result = new HashMap<>();
        try {
            Map<String, Object> parsedData = objectMapper.readValue(jsonData, 
                new TypeReference<Map<String, Object>>() {});
            result.put("data", parsedData);
        } catch (Exception e) {
            // ruleid: java-object-mapper-exception
            // Just logging without proper handling
            System.out.println("Error occurred");
        }
        return result;
    }
    
    @PostMapping("/bad_case_3")
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
        try {
            String body = request.getReader().lines()
                .reduce("", (accumulator, actual) -> accumulator + actual);
            UserCredentials credentials = objectMapper.readValue(body, UserCredentials.class);
            response.getWriter().write("Authentication successful");
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            // Swallowing exception and returning generic message
            try {
                response.getWriter().write("Error processing request");
            } catch (IOException ex) {
                // Nested exception handling
            }
        }
    }
    
    @PostMapping("/bad_case_4")
    public List<Product> bad_case_4(@RequestBody String jsonProductList) {
        List<Product> products = new ArrayList<>();
        try {
            products = objectMapper.readValue(jsonProductList, 
                new TypeReference<List<Product>>() {});
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            // Just returning empty list without proper error handling
        }
        return products;
    }
    
    @GetMapping("/bad_case_5")
    public Order bad_case_5(HttpServletRequest request) {
        String orderJson = request.getParameter("order");
        Order order = new Order();
        try {
            order = objectMapper.readValue(orderJson, Order.class);
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            // Returning default object without handling exception
        }
        return order;
    }
    
    @PostMapping("/bad_case_6")
    public boolean bad_case_6(@RequestBody String configJson) {
        try {
            Configuration config = objectMapper.readValue(configJson, Configuration.class);
            return config.isValid();
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            // Returning false without proper error handling
            return false;
        }
    }
    
    @PostMapping("/bad_case_7")
    public void bad_case_7(HttpServletRequest request) {
        try {
            String payload = request.getParameter("data");
            DataPayload dataPayload = objectMapper.readValue(payload, DataPayload.class);
            processData(dataPayload);
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            logger.debug("Error parsing JSON");
            // No rethrow or proper handling
        }
    }
    
    @PostMapping("/bad_case_8")
    public String bad_case_8(@RequestBody String jsonInput) {
        Settings settings = null;
        try {
            File configFile = new File("config.json");
            settings = objectMapper.readValue(configFile, Settings.class);
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            // Just printing stack trace without proper handling
            e.printStackTrace();
        }
        return "Settings loaded: " + (settings != null);
    }
    
    @PostMapping("/bad_case_9")
    public void bad_case_9(@RequestBody String jsonRequest) {
        try {
            RequestData data = objectMapper.readValue(jsonRequest, RequestData.class);
            processRequestData(data);
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            // Just setting a flag without proper handling
            boolean hasError = true;
        }
    }
    
    @PostMapping("/bad_case_10")
    public Map<String, Object> bad_case_10(@RequestBody String jsonData) {
        Map<String, Object> response = new HashMap<>();
        try {
            Map<String, Object> data = objectMapper.readValue(jsonData, 
                new TypeReference<Map<String, Object>>() {});
            response.putAll(data);
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            // Adding error message to response but not handling exception properly
            response.put("status", "error");
        }
        return response;
    }
    
    @PostMapping("/bad_case_11")
    public void bad_case_11(HttpServletRequest request) {
        String jsonBody = "";
        try {
            jsonBody = request.getReader().lines()
                .reduce("", (accumulator, actual) -> accumulator + actual);
            UserProfile profile = objectMapper.readValue(jsonBody, UserProfile.class);
            updateUserProfile(profile);
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            // Commenting out the exception handling
            // Should handle this exception properly
        }
    }
    
    @PostMapping("/bad_case_12")
    public String bad_case_12(@RequestBody String jsonInput) {
        try {
            ApiRequest apiRequest = objectMapper.readValue(jsonInput, ApiRequest.class);
            return processApiRequest(apiRequest);
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            // Using null coalescing but not handling exception
            return null;
        }
    }
    
    @PostMapping("/bad_case_13")
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) {
        try {
            String json = request.getParameter("config");
            ServerConfig config = objectMapper.readValue(json, ServerConfig.class);
            applyServerConfig(config);
        } catch (Exception e) {
            // ruleid: java-object-mapper-exception
            // Using a generic catch block and ignoring the exception
            // This is bad practice
        }
    }
    
    @PostMapping("/bad_case_14")
    public List<String> bad_case_14(@RequestBody String jsonArray) {
        List<String> items = new ArrayList<>();
        try {
            items = objectMapper.readValue(jsonArray, new TypeReference<List<String>>() {});
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            // Logging at trace level and not handling properly
            logger.trace("Error parsing JSON array", e);
        }
        return items;
    }
    
    @PostMapping("/bad_case_15")
    public void bad_case_15(@RequestBody String eventJson) {
        try {
            Event event = objectMapper.readValue(eventJson, Event.class);
            processEvent(event);
        } catch (IOException e) {
            // ruleid: java-object-mapper-exception
            // Just incrementing a counter without proper handling
            incrementErrorCounter();
        }
    }
    
    // True Negative Examples (Secure Code)
    
    @PostMapping("/good_case_1")
    public String good_case_1(@RequestBody String jsonInput) {
        User user = null;
        try {
            user = objectMapper.readValue(jsonInput, User.class);
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("Failed to parse user JSON", e);
            throw new RuntimeException("Invalid user data format", e);
        }
        return "Processed user: " + user.getName();
    }
    
    @PostMapping("/good_case_2")
    public Map<String, Object> good_case_2(@RequestBody String jsonData) {
        Map<String, Object> result = new HashMap<>();
        try {
            Map<String, Object> parsedData = objectMapper.readValue(jsonData, 
                new TypeReference<Map<String, Object>>() {});
            result.put("data", parsedData);
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("Error parsing JSON data", e);
            result.put("error", "Invalid JSON format: " + e.getMessage());
            throw new IllegalArgumentException("Invalid JSON data", e);
        }
        return result;
    }
    
    @PostMapping("/good_case_3")
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
        try {
            String body = request.getReader().lines()
                .reduce("", (accumulator, actual) -> accumulator + actual);
            UserCredentials credentials = objectMapper.readValue(body, UserCredentials.class);
            response.getWriter().write("Authentication successful");
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("Failed to process authentication request", e);
            try {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("Error: " + e.getMessage());
            } catch (IOException ex) {
                logger.error("Failed to send error response", ex);
            }
        }
    }
    
    @PostMapping("/good_case_4")
    public List<Product> good_case_4(@RequestBody String jsonProductList) throws IOException {
        // ok: java-object-mapper-exception
        // Properly declaring that this method throws IOException
        return objectMapper.readValue(jsonProductList, new TypeReference<List<Product>>() {});
    }
    
    @GetMapping("/good_case_5")
    public Order good_case_5(HttpServletRequest request) {
        String orderJson = request.getParameter("order");
        try {
            return objectMapper.readValue(orderJson, Order.class);
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("Failed to parse order JSON", e);
            throw new IllegalArgumentException("Invalid order format", e);
        }
    }
    
    @PostMapping("/good_case_6")
    public boolean good_case_6(@RequestBody String configJson) {
        try {
            Configuration config = objectMapper.readValue(configJson, Configuration.class);
            return config.isValid();
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("Failed to parse configuration", e);
            throw new RuntimeException("Configuration parsing failed", e);
        }
    }
    
    @PostMapping("/good_case_7")
    public ResponseEntity<String> good_case_7(HttpServletRequest request) {
        try {
            String payload = request.getParameter("data");
            DataPayload dataPayload = objectMapper.readValue(payload, DataPayload.class);
            processData(dataPayload);
            return ResponseEntity.ok("Data processed successfully");
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("Error parsing JSON payload", e);
            return ResponseEntity.badRequest().body("Invalid JSON format: " + e.getMessage());
        }
    }
    
    @PostMapping("/good_case_8")
    public String good_case_8(@RequestBody String jsonInput) {
        Settings settings = null;
        try {
            File configFile = new File("config.json");
            settings = objectMapper.readValue(configFile, Settings.class);
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("Failed to load settings from file", e);
            settings = new Settings(); // Use default settings
            saveErrorReport(e); // Log error for later analysis
        }
        return "Settings loaded: " + (settings != null);
    }
    
    @PostMapping("/good_case_9")
    public void good_case_9(@RequestBody String jsonRequest) {
        try {
            RequestData data = objectMapper.readValue(jsonRequest, RequestData.class);
            processRequestData(data);
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("Failed to parse request data", e);
            sendErrorNotification("Request parsing failed: " + e.getMessage());
            throw new BadRequestException("Invalid request format", e);
        }
    }
    
    @PostMapping("/good_case_10")
    public Map<String, Object> good_case_10(@RequestBody String jsonData) {
        Map<String, Object> response = new HashMap<>();
        try {
            Map<String, Object> data = objectMapper.readValue(jsonData, 
                new TypeReference<Map<String, Object>>() {});
            response.putAll(data);
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("JSON parsing error", e);
            response.put("status", "error");
            response.put("message", "Invalid JSON format: " + e.getMessage());
            response.put("errorType", e.getClass().getSimpleName());
        }
        return response;
    }
    
    @PostMapping("/good_case_11")
    public void good_case_11(HttpServletRequest request) throws IOException {
        String jsonBody = request.getReader().lines()
            .reduce("", (accumulator, actual) -> accumulator + actual);
        try {
            UserProfile profile = objectMapper.readValue(jsonBody, UserProfile.class);
            updateUserProfile(profile);
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("Failed to parse user profile", e);
            sendErrorMetrics("profile_parse_error", e);
            throw new InvalidDataException("Invalid profile data", e);
        }
    }
    
    @PostMapping("/good_case_12")
    public String good_case_12(@RequestBody String jsonInput) {
        try {
            ApiRequest apiRequest = objectMapper.readValue(jsonInput, ApiRequest.class);
            return processApiRequest(apiRequest);
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("API request parsing failed", e);
            recordFailedRequest(jsonInput, e);
            return "ERROR: " + e.getMessage();
        }
    }
    
    @PostMapping("/good_case_13")
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) {
        try {
            String json = request.getParameter("config");
            ServerConfig config = objectMapper.readValue(json, ServerConfig.class);
            applyServerConfig(config);
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("Server configuration parsing error", e);
            try {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("Invalid configuration format: " + e.getMessage());
            } catch (IOException ex) {
                logger.error("Failed to send error response", ex);
            }
        }
    }
    
    @PostMapping("/good_case_14")
    public List<String> good_case_14(@RequestBody String jsonArray) {
        try {
            // ok: java-object-mapper-exception
            return objectMapper.readValue(jsonArray, new TypeReference<List<String>>() {});
        } catch (IOException e) {
            logger.error("Failed to parse JSON array", e);
            throw new JsonParseException("Invalid JSON array format", e);
        }
    }
    
    @PostMapping("/good_case_15")
    public void good_case_15(@RequestBody String eventJson) {
        try {
            Event event = objectMapper.readValue(eventJson, Event.class);
            processEvent(event);
        } catch (IOException e) {
            // ok: java-object-mapper-exception
            logger.error("Event processing failed", e);
            notifyAdministrator("Event processing error: " + e.getMessage());
            throw new ServiceException("Failed to process event", e);
        }
    }
    
    // Helper methods and classes to support the examples
    private void processData(DataPayload data) {
        // Process the data
    }
    
    private void updateUserProfile(UserProfile profile) {
        // Update user profile
    }
    
    private String processApiRequest(ApiRequest request) {
        return "Processed: " + request.toString();
    }
    
    private void applyServerConfig(ServerConfig config) {
        // Apply server configuration
    }
    
    private void processEvent(Event event) {
        // Process the event
    }
    
    private void incrementErrorCounter() {
        // Increment error counter
    }
    
    private void saveErrorReport(Exception e) {
        // Save error report
    }
    
    private void sendErrorNotification(String message) {
        // Send error notification
    }
    
    private void sendErrorMetrics(String metricName, Exception e) {
        // Send error metrics
    }
    
    private void recordFailedRequest(String request, Exception e) {
        // Record failed request
    }
    
    private void notifyAdministrator(String message) {
        // Notify administrator
    }
    
    // Simple classes for the examples
    static class User {
        private String name;
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }
    
    static class UserCredentials {
        private String username;
        private String password;
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
    
    static class Product {
        private String id;
        private String name;
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }
    
    static class Order {
        private String orderId;
        private double amount;
        public String getOrderId() { return orderId; }
        public void setOrderId(String orderId) { this.orderId = orderId; }
        public double getAmount() { return amount; }
        public void setAmount(double amount) { this.amount = amount; }
    }
    
    static class Configuration {
        private boolean valid;
        public boolean isValid() { return valid; }
        public void setValid(boolean valid) { this.valid = valid; }
    }
    
    static class DataPayload {
        private String data;
        public String getData() { return data; }
        public void setData(String data) { this.data = data; }
    }
    
    static class Settings {
        private Map<String, String> properties = new HashMap<>();
        public Map<String, String> getProperties() { return properties; }
        public void setProperties(Map<String, String> properties) { this.properties = properties; }
    }
    
    static class RequestData {
        private String type;
        private String content;
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }
    }
    
    static class UserProfile {
        private String userId;
        private Map<String, Object> preferences;
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public Map<String, Object> getPreferences() { return preferences; }
        public void setPreferences(Map<String, Object> preferences) { this.preferences = preferences; }
    }
    
    static class ApiRequest {
        private String action;
        private Map<String, Object> parameters;
        public String getAction() { return action; }
        public void setAction(String action) { this.action = action; }
        public Map<String, Object> getParameters() { return parameters; }
        public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }
    }
    
    static class ServerConfig {
        private int port;
        private String host;
        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }
        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }
    }
    
    static class Event {
        private String type;
        private String payload;
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getPayload() { return payload; }
        public void setPayload(String payload) { this.payload = payload; }
    }
    
    // Custom exceptions
    static class BadRequestException extends RuntimeException {
        public BadRequestException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    static class InvalidDataException extends RuntimeException {
        public InvalidDataException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    static class JsonParseException extends RuntimeException {
        public JsonParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    static class ServiceException extends RuntimeException {
        public ServiceException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    // Mock ResponseEntity class for examples
    static class ResponseEntity<T> {
        private T body;
        private int status;
        
        private ResponseEntity(T body, int status) {
            this.body = body;
            this.status = status;
        }
        
        public static <T> ResponseEntity<T> ok(T body) {
            return new ResponseEntity<>(body, 200);
        }
        
        public static <T> ResponseEntity<T> badRequest() {
            return new ResponseEntity<>(null, 400);
        }
        
        public ResponseEntity<T> body(T body) {
            this.body = body;
            return this;
        }
    }
}
// {/fact}