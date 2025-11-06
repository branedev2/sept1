import java.util.logging.Logger;
import java.util.logging.Level;
import org.slf4j.LoggerFactory;
import org.apache.log4j.LogManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import java.util.HashMap;
import java.util.Map;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.userdetails.User;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class InsecureObjectLoggingExamples {
    private static final Logger javaLogger = Logger.getLogger(InsecureObjectLoggingExamples.class.getName());
    private static final org.slf4j.Logger slf4jLogger = LoggerFactory.getLogger(InsecureObjectLoggingExamples.class);
    private static final org.apache.log4j.Logger log4jLogger = LogManager.getLogger(InsecureObjectLoggingExamples.class);
    private static final Log commonsLogger = LogFactory.getLog(InsecureObjectLoggingExamples.class);

    // Class with sensitive data
    static class UserCredentials {
        private String username;
        private String password;
        private String ssn;
        private String apiKey;
        
        public UserCredentials(String username, String password, String ssn, String apiKey) {
            this.username = username;
            this.password = password;
            this.ssn = ssn;
            this.apiKey = apiKey;
        }
        
        public String getUsername() { return username; }
        public String getPassword() { return password; }
        public String getSsn() { return ssn; }
        public String getApiKey() { return apiKey; }
        
        // No custom toString() implementation
    }
    
    // Class with custom toString that still leaks sensitive data
    static class PaymentInfo {
        private String cardNumber;
        private String cvv;
        private String expiryDate;
        
        public PaymentInfo(String cardNumber, String cvv, String expiryDate) {
            this.cardNumber = cardNumber;
            this.cvv = cvv;
            this.expiryDate = expiryDate;
        }
        
        @Override
        public String toString() {
            return "PaymentInfo{cardNumber='" + cardNumber + "', cvv='" + cvv + "', expiryDate='" + expiryDate + "'}";
        }
    }
    
    // Class with proper toString implementation
    static class SecureUserCredentials {
        private String username;
        private String password;
        private String ssn;
        private String apiKey;
        
        public SecureUserCredentials(String username, String password, String ssn, String apiKey) {
            this.username = username;
            this.password = password;
            this.ssn = ssn;
            this.apiKey = apiKey;
        }
        
        @Override
        public String toString() {
            return "SecureUserCredentials{username='" + username + "', password='[REDAC_REDACTED_TWILIO_ID]', ssn='[REDAC_REDACTED_TWILIO_ID]', apiKey='[REDAC_REDACTED_TWILIO_ID]'}";
        }
    }
    
    // Class with proper toString implementation for payment info
    static class SecurePaymentInfo {
        private String cardNumber;
        private String cvv;
        private String expiryDate;
        
        public SecurePaymentInfo(String cardNumber, String cvv, String expiryDate) {
            this.cardNumber = cardNumber;
            this.cvv = cvv;
            this.expiryDate = expiryDate;
        }
        
        @Override
        public String toString() {
            return "SecurePaymentInfo{cardNumber='" + maskCardNumber(cardNumber) + "', cvv='[REDAC_REDACTED_TWILIO_ID]', expiryDate='" + expiryDate + "'}";
        }
        
        private String maskCardNumber(String number) {
            if (number == null || number.length() < 4) return "[INVALID]";
            return "XXXX-XXXX-XXXX-" + number.substring(number.length() - 4);
        }
    }

    // TRUE POSITIVES - Vulnerable code examples

// {fact rule=log-injection@v1.0 defects=1}
    @Controller
    public void bad_case_1(HttpServletRequest request) {
        UserCredentials credentials = new UserCredentials(
            request.getParameter("username"),
            request.getParameter("password"),
            request.getParameter("ssn"),
            request.getParameter("apiKey")
        );
        
        // ruleid: java-insecure-object-logging
        javaLogger.info("User credentials: " + credentials);
    }
    
    @RestController
    @RequestMapping("/api")
    public static class BadController1 {
        @PostMapping("/payment")
        public void bad_case_2(@RequestBody PaymentInfo paymentInfo) {
            // ruleid: java-insecure-object-logging
            slf4jLogger.info("Received payment info: {}", paymentInfo);
        }
    }
    
    public void bad_case_3() {
        Map<String, String> configMap = new HashMap<>();
        configMap.put("dbUser", "admin");
        configMap.put("dbPassword", "super_secret_password");
        configMap.put("apiToken", "1234567890abcdef");
        
        // ruleid: java-insecure-object-logging
        log4jLogger.info("Application configuration: " + configMap);
    }
    
    @Controller
    public void bad_case_4(HttpServletRequest request) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        Map<String, Object> userMap = new HashMap<>();
        userMap.put("username", username);
        userMap.put("password", password);
        userMap.put("loginTime", System.currentTimeMillis());
        
        // ruleid: java-insecure-object-logging
        commonsLogger.info("User login attempt: " + userMap);
    }
    
    public void bad_case_5() {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb",
                "root",
                "password123"
            );
            
            // ruleid: java-insecure-object-logging
            javaLogger.info("Database connection established: " + conn);
        } catch (SQLException e) {
            javaLogger.severe("Connection failed: " + e.getMessage());
        }
    }
    
    @RestController
    public static class BadController2 {
        @GetMapping("/user/{id}")
        public void bad_case_6(@PathVariable String id, HttpServletRequest request) {
            User user = new org.springframework.security.core.userdetails.User(
                request.getParameter("username"),
                request.getParameter("password"),
                Arrays.asList()
            );
            
            // ruleid: java-insecure-object-logging
            slf4jLogger.debug("User object: {}", user);
        }
    }
    
    public void bad_case_7(HttpServletRequest request) {
        List<String> sensitiveData = Arrays.asList(
            request.getParameter("ssn"),
            request.getParameter("creditCard"),
            request.getParameter("password")
        );
        
        // ruleid: java-insecure-object-logging
        log4jLogger.info("Collected sensitive data: " + sensitiveData);
    }
    
    @Controller
    public void bad_case_8(HttpServletRequest request) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            UserCredentials credentials = mapper.readValue(request.getInputStream(), UserCredentials.class);
            
            // ruleid: java-insecure-object-logging
            javaLogger.log(Level.INFO, "Parsed credentials: {0}", credentials);
        } catch (Exception e) {
            javaLogger.severe("Failed to parse: " + e.getMessage());
        }
    }
    
    public void bad_case_9() {
        PaymentInfo paymentInfo = new PaymentInfo(
            "4111-1111-1111-1111",
            "123",
            "12/25"
        );
        
        // ruleid: java-insecure-object-logging
        slf4jLogger.info("Processing payment with: {}", paymentInfo);
    }
    
    @RestController
    public static class BadController3 {
        @PostMapping("/register")
        public void bad_case_10(@RequestBody Map<String, String> formData) {
            // ruleid: java-insecure-object-logging
            log4jLogger.info("Registration data: " + formData);
        }
    }
    
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) {
        Map<String, Object> sessionData = new HashMap<>();
        sessionData.put("sessionId", request.getSession().getId());
        sessionData.put("authToken", request.getHeader("Authorization"));
        sessionData.put("ipAddress", request.getRemoteAddr());
        
        // ruleid: java-insecure-object-logging
        commonsLogger.info(sessionData);
    }
    
    @Controller
    public void bad_case_12() {
        Exception exception = new Exception("Authentication failed");
        Map<String, Object> errorContext = new HashMap<>();
        errorContext.put("timestamp", System.currentTimeMillis());
        errorContext.put("adminPassword", "admin123");
        errorContext.put("exception", exception);
        
        // ruleid: java-insecure-object-logging
        javaLogger.severe("Error occurred: " + errorContext);
    }
    
    public void bad_case_13(HttpServletRequest request) {
        String[] sensitiveFields = {
            request.getParameter("password"),
            request.getParameter("token"),
            request.getParameter("pin")
        };
        
        // ruleid: java-insecure-object-logging
        slf4jLogger.warn("Security alert! Sensitive fields accessed: {}", (Object) sensitiveFields);
    }
    
    @RestController
    public static class BadController4 {
        @PostMapping("/authenticate")
        public void bad_case_14(@RequestBody UserCredentials credentials) {
            try {
                // Some authentication logic
                throw new RuntimeException("Authentication failed");
            } catch (Exception e) {
                // ruleid: java-insecure-object-logging
                log4jLogger.error("Authentication failed for credentials: " + credentials, e);
            }
        }
    }
    
    public void bad_case_15(HttpServletRequest request) {
        Map<String, String[]> allParameters = request.getParameterMap();
        
        // ruleid: java-insecure-object-logging
        javaLogger.info("All request parameters: " + allParameters);
    }

    // TRUE NEGATIVES - Secure code examples
    
    @Controller
    public void good_case_1(HttpServletRequest request) {
        UserCredentials credentials = new UserCredentials(
            request.getParameter("username"),
            request.getParameter("password"),
            request.getParameter("ssn"),
            request.getParameter("apiKey")
        );
        
        // ok: java-insecure-object-logging
        javaLogger.info("User login attempt for username: " + credentials.getUsername());
    }
    
    @RestController
    @RequestMapping("/api")
    public static class GoodController1 {
        @PostMapping("/payment")
        public void good_case_2(@RequestBody PaymentInfo paymentInfo) {
            String maskedCardNumber = "XXXX-XXXX-XXXX-" + 
                paymentInfo.cardNumber.substring(paymentInfo.cardNumber.length() - 4);
            
            // ok: java-insecure-object-logging
            slf4jLogger.info("Received payment with card: {}, expiry: {}", 
                maskedCardNumber, paymentInfo.expiryDate);
        }
    }
    
    public void good_case_3() {
        Map<String, String> configMap = new HashMap<>();
        configMap.put("dbUser", "admin");
        configMap.put("dbPassword", "super_secret_password");
        configMap.put("apiToken", "1234567890abcdef");
        
        Map<String, String> safeConfigMap = new HashMap<>();
        safeConfigMap.put("dbUser", configMap.get("dbUser"));
        safeConfigMap.put("dbPassword", "[REDAC_REDACTED_TWILIO_ID]");
        safeConfigMap.put("apiToken", "[REDAC_REDACTED_TWILIO_ID]");
        
        // ok: java-insecure-object-logging
        log4jLogger.info("Application configuration: " + safeConfigMap);
    }
    
    @Controller
    public void good_case_4(HttpServletRequest request) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // ok: java-insecure-object-logging
        commonsLogger.info("User login attempt for username: " + username + ", password: [REDAC_REDACTED_TWILIO_ID]");
    }
    
    public void good_case_5() {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb",
                "root",
                "password123"
            );
            
            // ok: java-insecure-object-logging
            javaLogger.info("Database connection established to: jdbc:mysql://localhost:3306/mydb");
        } catch (SQLException e) {
            javaLogger.severe("Connection failed: " + e.getMessage());
        }
    }
    
    @RestController
    public static class GoodController2 {
        @GetMapping("/user/{id}")
        public void good_case_6(@PathVariable String id, HttpServletRequest request) {
            User user = new org.springframework.security.core.userdetails.User(
                request.getParameter("username"),
                request.getParameter("password"),
                Arrays.asList()
            );
            
            // ok: java-insecure-object-logging
            slf4jLogger.debug("User authenticated: {}", user.getUsername());
        }
    }
    
    public void good_case_7(HttpServletRequest request) {
        String ssn = request.getParameter("ssn");
        String creditCard = request.getParameter("creditCard");
        String password = request.getParameter("password");
        
        // ok: java-insecure-object-logging
        log4jLogger.info("Received sensitive data fields: SSN [REDAC_REDACTED_TWILIO_ID], " +
                         "Credit Card [REDAC_REDACTED_TWILIO_ID], Password [REDAC_REDACTED_TWILIO_ID]");
    }
    
    @Controller
    public void good_case_8(HttpServletRequest request) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            UserCredentials credentials = mapper.readValue(request.getInputStream(), UserCredentials.class);
            
            // ok: java-insecure-object-logging
            javaLogger.log(Level.INFO, "User {0} attempting to authenticate", credentials.getUsername());
        } catch (Exception e) {
            javaLogger.severe("Failed to parse: " + e.getMessage());
        }
    }
    
    public void good_case_9() {
        SecurePaymentInfo paymentInfo = new SecurePaymentInfo(
            "4111-1111-1111-1111",
            "123",
            "12/25"
        );
        
        // ok: java-insecure-object-logging
        slf4jLogger.info("Processing payment: {}", paymentInfo);
    }
    
    @RestController
    public static class GoodController3 {
        @PostMapping("/register")
        public void good_case_10(@RequestBody Map<String, String> formData) {
            Map<String, String> safeData = new HashMap<>();
            
            // Copy only non-sensitive fields or mask sensitive ones
            for (Map.Entry<String, String> entry : formData.entrySet()) {
                String key = entry.getKey();
                if (key.contains("password") || key.contains("secret") || 
                    key.contains("token") || key.contains("ssn") || 
                    key.contains("credit")) {
                    safeData.put(key, "[REDAC_REDACTED_TWILIO_ID]");
                } else {
                    safeData.put(key, entry.getValue());
                }
            }
            
            // ok: java-insecure-object-logging
            log4jLogger.info("Registration data: " + safeData);
        }
    }
    
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) {
        // ok: java-insecure-object-logging
        commonsLogger.info("Session ID: " + request.getSession().getId() + 
                          ", IP Address: " + request.getRemoteAddr());
    }
    
    @Controller
    public void good_case_12() {
        Exception exception = new Exception("Authentication failed");
        
        // ok: java-insecure-object-logging
        javaLogger.log(Level.SEVERE, "Authentication error occurred", exception);
    }
    
    public void good_case_13(HttpServletRequest request) {
        String password = request.getParameter("password");
        String token = request.getParameter("token");
        String pin = request.getParameter("pin");
        
        // ok: java-insecure-object-logging
        slf4jLogger.warn("Security alert! Sensitive fields accessed: password=[REDAC_REDACTED_TWILIO_ID], token=[REDAC_REDACTED_TWILIO_ID], pin=[REDAC_REDACTED_TWILIO_ID]");
    }
    
    @RestController
    public static class GoodController4 {
        @PostMapping("/authenticate")
        public void good_case_14(@RequestBody UserCredentials credentials) {
            try {
                // Some authentication logic
                throw new RuntimeException("Authentication failed");
            } catch (Exception e) {
                // ok: java-insecure-object-logging
                log4jLogger.error("Authentication failed for user: " + credentials.getUsername(), e);
            }
        }
    }
    
    public void good_case_15(HttpServletRequest request) {
        Map<String, String[]> allParameters = request.getParameterMap();
        Map<String, Object> safeParameters = new HashMap<>();
        
        for (Map.Entry<String, String[]> entry : allParameters.entrySet()) {
            String key = entry.getKey();
            if (key.toLowerCase().contains("password") || 
                key.toLowerCase().contains("secret") || 
                key.toLowerCase().contains("token") || 
                key.toLowerCase().contains("key")) {
                safeParameters.put(key, "[REDAC_REDACTED_TWILIO_ID]");
            } else {
                safeParameters.put(key, entry.getValue());
            }
        }
        
        // ok: java-insecure-object-logging
        javaLogger.info("Request parameters (sanitized): " + safeParameters);
    }
}
// {/fact}