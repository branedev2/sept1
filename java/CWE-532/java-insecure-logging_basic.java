import java.util.logging.Logger;
import java.util.logging.Level;
import org.apache.log4j.LogManager;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.io.IOException;
import java.util.Properties;
import java.util.Base64;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3Client;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Map;
import java.util.HashMap;

@RestController
public class InsecureLoggingExamples {
    private static final Logger javaLogger = Logger.getLogger(InsecureLoggingExamples.class.getName());
    private static final org.apache.log4j.Logger log4jLogger = LogManager.getLogger(InsecureLoggingExamples.class);
    private static final org.slf4j.Logger slf4jLogger = LoggerFactory.getLogger(InsecureLoggingExamples.class);

    // True Positive Examples (Vulnerable Code)

// {fact rule=log-injection@v1.0 defects=1}
    @RequestMapping("/bad_case_1")
    public String bad_case_1(HttpServletRequest request) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // ruleid: java-insecure-logging
        javaLogger.info("User login attempt with username: " + username + " and password: " + password);
        
        // Authentication logic would go here
        return "Login processed";
    }

    @RequestMapping("/bad_case_2")
    public String bad_case_2(HttpServletRequest request) {
        String apiKey = request.getHeader("X-API-Key");
        
        // ruleid: java-insecure-logging
        log4jLogger.info("API request received with key: " + apiKey);
        
        // API processing logic would go here
        return "API request processed";
    }

    @RequestMapping("/bad_case_3")
    public String bad_case_3(HttpServletRequest request) {
        String creditCardNumber = request.getParameter("ccNumber");
        
        // ruleid: java-insecure-logging
        slf4jLogger.info("Processing payment with credit card: {}", creditCardNumber);
        
        // Payment processing logic would go here
        return "Payment processed";
    }

    @RequestMapping("/bad_case_4")
    public String bad_case_4(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            // ruleid: java-insecure-logging
            javaLogger.log(Level.INFO, "Cookie name: " + cookie.getName() + ", value: " + cookie.getValue());
        }
        
        return "Cookies processed";
    }

    @RequestMapping("/bad_case_5")
    public String bad_case_5() {
        String dbUrl = "jdbc:mysql://localhost:3306/mydb";
        String dbUser = "admin";
        String dbPassword = "s3cr3tP@ssw0rd";
        
        try {
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPassword);
            // ruleid: java-insecure-logging
            log4jLogger.info("Connected to database with credentials - URL: " + dbUrl + 
                            ", User: " + dbUser + ", Password: " + dbPassword);
            return "Database connected";
        } catch (SQLException e) {
            return "Connection failed";
        }
    }

    @RequestMapping("/bad_case_6")
    public String bad_case_6(HttpServletRequest request) {
        String ssn = request.getParameter("ssn");
        String formattedSSN = ssn.replaceAll("-", "");
        
        // ruleid: java-insecure-logging
        slf4jLogger.info("Processing user with SSN: {}", formattedSSN);
        
        // User processing logic would go here
        return "User processed";
    }

    @RequestMapping("/bad_case_7")
    public String bad_case_7() {
        AWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        AmazonS3Client s3Client = new AmazonS3Client(credentials);
        
        // ruleid: java-insecure-logging
        javaLogger.info("Initialized AWS S3 client with Access Key: " + credentials.getAWSAccessKeyId() + 
                       " and Secret Key: " + credentials.getAWSSecretKey());
        
        return "AWS client initialized";
    }

    @RequestMapping("/bad_case_8")
    public String bad_case_8(HttpServletRequest request) {
        String authToken = request.getHeader("Authorization");
        
        if (authToken != null && authToken.startsWith("Bearer ")) {
            String token = authToken.substring(7);
            // ruleid: java-insecure-logging
            log4jLogger.info("Processing request with JWT token: " + token);
        }
        
        return "Auth processed";
    }

    @RequestMapping("/bad_case_9")
    public String bad_case_9() {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.user", "user@example.com");
        props.put("mail.smtp.password", "emailP@ssw0rd");
        
        // ruleid: java-insecure-logging
        slf4jLogger.info("Email configuration: {}", props);
        
        return "Email configured";
    }

    @RequestMapping("/bad_case_10")
    public String bad_case_10(HttpServletRequest request) {
        String privateKey = request.getParameter("privateKey");
        
        // ruleid: java-insecure-logging
        javaLogger.severe("Error processing private key: " + privateKey);
        
        return "Key processed";
    }

    @RequestMapping("/bad_case_11")
    public String bad_case_11() {
        String encryptionKey = "1234567890abcdef";
        SecretKey secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
        
        // ruleid: java-insecure-logging
        log4jLogger.info("Using encryption key: " + encryptionKey + " with algorithm AES");
        
        return "Encryption initialized";
    }

    @RequestMapping("/bad_case_12")
    public String bad_case_12(HttpServletRequest request) {
        Map<String, String> userDetails = new HashMap<>();
        userDetails.put("name", request.getParameter("name"));
        userDetails.put("email", request.getParameter("email"));
        userDetails.put("password", request.getParameter("password"));
        
        // ruleid: java-insecure-logging
        slf4jLogger.info("User registration details: {}", userDetails);
        
        return "User registered";
    }

    @RequestMapping("/bad_case_13")
    public String bad_case_13(HttpServletRequest request) {
        String base64Credentials = request.getHeader("Authorization").substring("Basic ".length());
        String credentials = new String(Base64.getDecoder().decode(base64Credentials));
        
        // ruleid: java-insecure-logging
        javaLogger.info("Basic auth credentials: " + credentials);
        
        return "Auth processed";
    }

    @RequestMapping("/bad_case_14")
    public String bad_case_14() {
        try {
            throw new Exception("Error occurred with password: p@ssw0rd123");
        } catch (Exception e) {
            // ruleid: java-insecure-logging
            log4jLogger.error("Exception details: " + e.getMessage());
            return "Error handled";
        }
    }

    @RequestMapping("/bad_case_15")
    public String bad_case_15(HttpServletRequest request) {
        String otp = request.getParameter("otp");
        String phoneNumber = request.getParameter("phone");
        
        // ruleid: java-insecure-logging
        slf4jLogger.info("Sending OTP {} to phone number {}", otp, phoneNumber);
        
        return "OTP sent";
    }

    // True Negative Examples (Secure Code)

    @RequestMapping("/good_case_1")
    public String good_case_1(HttpServletRequest request) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // ok: java-insecure-logging
        javaLogger.info("User login attempt with username: " + username);
        
        // Authentication logic would go here
        return "Login processed";
    }

    @RequestMapping("/good_case_2")
    public String good_case_2(HttpServletRequest request) {
        String apiKey = request.getHeader("X-API-Key");
        
        if (apiKey != null) {
            // ok: java-insecure-logging
            log4jLogger.info("API request received with key: [REDAC_REDACTED_TWILIO_ID]");
        }
        
        return "API request processed";
    }

    @RequestMapping("/good_case_3")
    public String good_case_3(HttpServletRequest request) {
        String creditCardNumber = request.getParameter("ccNumber");
        
        if (creditCardNumber != null && creditCardNumber.length() >= 4) {
            String lastFourDigits = creditCardNumber.substring(creditCardNumber.length() - 4);
            // ok: java-insecure-logging
            slf4jLogger.info("Processing payment with credit card ending in: {}", lastFourDigits);
        }
        
        return "Payment processed";
    }

    @RequestMapping("/good_case_4")
    public String good_case_4(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (!cookie.getName().toLowerCase().contains("auth") && 
                    !cookie.getName().toLowerCase().contains("session")) {
                    // ok: java-insecure-logging
                    javaLogger.log(Level.INFO, "Non-sensitive cookie found: " + cookie.getName());
                } else {
                    // ok: java-insecure-logging
                    javaLogger.log(Level.INFO, "Sensitive cookie present: " + cookie.getName() + " [VALUE REDAC_REDACTED_TWILIO_ID]");
                }
            }
        }
        
        return "Cookies processed";
    }

    @RequestMapping("/good_case_5")
    public String good_case_5() {
        String dbUrl = "jdbc:mysql://localhost:3306/mydb";
        String dbUser = System.getenv("DB_USER");
        String dbPassword = System.getenv("DB_PASSWORD");
        
        try {
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPassword);
            // ok: java-insecure-logging
            log4jLogger.info("Connected to database with URL: " + dbUrl);
            return "Database connected";
        } catch (SQLException e) {
            return "Connection failed";
        }
    }

    @RequestMapping("/good_case_6")
    public String good_case_6(HttpServletRequest request) {
        String ssn = request.getParameter("ssn");
        
        if (ssn != null && ssn.length() >= 4) {
            String lastFourSSN = ssn.substring(ssn.length() - 4);
            // ok: java-insecure-logging
            slf4jLogger.info("Processing user with SSN ending in: {}", lastFourSSN);
        }
        
        return "User processed";
    }

    @RequestMapping("/good_case_7")
    public String good_case_7() {
        String accessKeyId = System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY_ID");
        String secretKey = System.getenv("AWS_SECRET_AC_REDACTED_TWILIO_ID_KEY");
        
        AWSCredentials credentials = new BasicAWSCredentials(accessKeyId, secretKey);
        AmazonS3Client s3Client = new AmazonS3Client(credentials);
        
        // ok: java-insecure-logging
        javaLogger.info("Initialized AWS S3 client with credentials from environment variables");
        
        return "AWS client initialized";
    }

    @RequestMapping("/good_case_8")
    public String good_case_8(HttpServletRequest request) {
        String authToken = request.getHeader("Authorization");
        
        if (authToken != null && authToken.startsWith("Bearer ")) {
            // ok: java-insecure-logging
            log4jLogger.info("Processing request with valid JWT token format");
        }
        
        return "Auth processed";
    }

    @RequestMapping("/good_case_9")
    public String good_case_9() {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.user", System.getenv("SMTP_USER"));
        props.put("mail.smtp.password", System.getenv("SMTP_PASSWORD"));
        
        // ok: java-insecure-logging
        slf4jLogger.info("Email configuration initialized with host: {}", props.getProperty("mail.smtp.host"));
        
        return "Email configured";
    }

    @RequestMapping("/good_case_10")
    public String good_case_10(HttpServletRequest request) {
        String privateKey = request.getParameter("privateKey");
        
        if (privateKey != null) {
            // ok: java-insecure-logging
            javaLogger.severe("Error processing private key: [REDAC_REDACTED_TWILIO_ID]");
        }
        
        return "Key processed";
    }

    @RequestMapping("/good_case_11")
    public String good_case_11() {
        String encryptionKey = System.getenv("ENCRYPTION_KEY");
        SecretKey secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
        
        // ok: java-insecure-logging
        log4jLogger.info("Using encryption key from environment variable with algorithm AES");
        
        return "Encryption initialized";
    }

    @RequestMapping("/good_case_12")
    public String good_case_12(HttpServletRequest request) {
        Map<String, String> userDetails = new HashMap<>();
        userDetails.put("name", request.getParameter("name"));
        userDetails.put("email", request.getParameter("email"));
        
        // Password is intentionally not added to the map
        
        // ok: java-insecure-logging
        slf4jLogger.info("User registration details (excluding password): {}", userDetails);
        
        return "User registered";
    }

    @RequestMapping("/good_case_13")
    public String good_case_13(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            // ok: java-insecure-logging
            javaLogger.info("Request received with Basic authentication");
        }
        
        return "Auth processed";
    }

    @RequestMapping("/good_case_14")
    public String good_case_14() {
        try {
            throw new Exception("Error occurred during processing");
        } catch (Exception e) {
            // ok: java-insecure-logging
            log4jLogger.error("Exception caught: " + e.getClass().getName() + " - " + 
                            e.getMessage().replaceAll("password:\\s*\\S+", "password: [REDAC_REDACTED_TWILIO_ID]"));
            return "Error handled";
        }
    }

    @RequestMapping("/good_case_15")
    public String good_case_15(HttpServletRequest request) {
        String phoneNumber = request.getParameter("phone");
        
        if (phoneNumber != null) {
            // ok: java-insecure-logging
            slf4jLogger.info("Sending OTP to phone number ending with: {}", 
                           phoneNumber.substring(Math.max(0, phoneNumber.length() - 4)));
        }
        
        return "OTP sent";
    }
}
// {/fact}