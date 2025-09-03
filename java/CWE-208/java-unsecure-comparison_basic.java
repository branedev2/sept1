# Vulnerability Analysis

This rule detects the use of `equals` method for comparing secrets, which is vulnerable to timing attacks. Instead, constant-time comparison methods like `MessageDigest.isEqual` should be used when comparing sensitive information.

This is a configuration/usage issue related to improper implementation of security-sensitive comparisons. The vulnerability allows potential timing attacks where an attacker can determine secret values by measuring the time taken for comparisons.

```java
import java.security.MessageDigest;
import java.util.Arrays;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.security.crypto.bcrypt.BCrypt;
import java.nio.charset.StandardCharsets;

public class UnsecureComparisonExamples {

    // True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String storedApiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
        String userProvidedApiKey = request.getHeader("X-API-Key");
        
        // ruleid: java-unsecure-comparison
        if (storedApiKey.equals(userProvidedApiKey)) {
            System.out.println("API key is valid");
        } else {
            System.out.println("API key is invalid");
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        String storedPassword = "supersecretpassword123";
        String userPassword = request.getParameter("password");
        
        // ruleid: java-unsecure-comparison
        if (userPassword != null && userPassword.equals(storedPassword)) {
            System.out.println("Password is correct");
        } else {
            System.out.println("Password is incorrect");
        }
    }

    public void bad_case_3(HttpServletRequest request) {
        byte[] storedToken = Base64.getDecoder().decode("c2VjcmV0dG9rZW4=");
        String userToken = request.getParameter("token");
        byte[] userTokenBytes = Base64.getDecoder().decode(userToken);
        
        String storedTokenStr = new String(storedToken, StandardCharsets.UTF_8);
        String userTokenStr = new String(userTokenBytes, StandardCharsets.UTF_8);
        
        // ruleid: java-unsecure-comparison
        if (storedTokenStr.equals(userTokenStr)) {
            System.out.println("Token is valid");
        }
    }

    @RestController
    public class bad_case_4 {
        private final String JWT_SECRET = "jwt_secret_key_12345";
        
        @PostMapping("/verify")
        public String verifyToken(@RequestHeader("Authorization") String authHeader) {
            String token = authHeader.substring(7); // Remove "Bearer " prefix
            String signature = extractSignature(token);
            String expectedSignature = calculateSignature(token, JWT_SECRET);
            
            // ruleid: java-unsecure-comparison
            if (signature.equals(expectedSignature)) {
                return "Token is valid";
            }
            return "Token is invalid";
        }
        
        private String extractSignature(String token) {
            String[] parts = token.split("\\.");
            return parts[2];
        }
        
        private String calculateSignature(String token, String secret) {
            // Simplified for example
            return "calculated_signature";
        }
    }

    public void bad_case_5(HttpServletRequest request) {
        String storedHash = "5f4dcc3b5aa765d61d8327deb882cf99"; // MD5 hash of "password"
        String userPassword = request.getParameter("password");
        String userHash = getMD5Hash(userPassword);
        
        // ruleid: java-unsecure-comparison
        if (storedHash.equals(userHash)) {
            System.out.println("Password is correct");
        }
    }
    
    private String getMD5Hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        String correctOTP = "123456";
        String userOTP = request.getParameter("otp");
        
        // ruleid: java-unsecure-comparison
        boolean isValid = correctOTP.equals(userOTP);
        if (isValid) {
            System.out.println("OTP verification successful");
        }
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) {
        String storedCSRFToken = "random_csrf_token_value";
        String userCSRFToken = request.getParameter("csrf_token");
        
        // ruleid: java-unsecure-comparison
        if (!storedCSRFToken.equals(userCSRFToken)) {
            response.setStatus(403);
            return;
        }
        
        System.out.println("CSRF token is valid");
    }

    @RestController
    public class bad_case_8 {
        private final String API_SECRET = "api_secret_12345";
        
        @GetMapping("/webhook")
        public String handleWebhook(@RequestParam String payload, @RequestParam String signature) {
            String calculatedSignature = calculateHMAC_REDACTED_TWILIO_ID(payload, API_SECRET);
            
            // ruleid: java-unsecure-comparison
            if (calculatedSignature.equals(signature)) {
                return "Webhook signature verified";
            }
            return "Invalid signature";
        }
        
        private String calculateHMAC_REDACTED_TWILIO_ID(String data, String key) {
            try {
                Mac sha256_HMAC_REDACTED_TWILIO_ID = Mac.getInstance("HmacSHA256");
                SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
                sha256_HMAC_REDACTED_TWILIO_ID.init(secret_key);
                return Base64.getEncoder().encodeToString(sha256_HMAC_REDACTED_TWILIO_ID.doFinal(data.getBytes("UTF-8")));
            } catch (Exception e) {
                return "";
            }
        }
    }

    public void bad_case_9(HttpServletRequest request) {
        String storedEncryptionKey = "encryption_key_12345";
        String userProvidedKey = request.getParameter("key");
        
        // ruleid: java-unsecure-comparison
        if (storedEncryptionKey.equals(userProvidedKey)) {
            System.out.println("Encryption key is valid");
        } else {
            System.out.println("Invalid encryption key");
        }
    }

    public void bad_case_10(HttpServletRequest request) {
        byte[] secretBytes = "secret_bytes_value".getBytes();
        String userInput = request.getParameter("secret");
        byte[] userBytes = userInput.getBytes();
        
        // ruleid: java-unsecure-comparison
        boolean isEqual = Arrays.equals(secretBytes, userBytes);
        if (isEqual) {
            System.out.println("Secret is valid");
        }
    }

    public void bad_case_11(HttpServletRequest request) {
        String storedPin = "1234";
        String userPin = request.getParameter("pin");
        
        // ruleid: java-unsecure-comparison
        if (storedPin.equals(userPin)) {
            System.out.println("PIN is correct");
        } else {
            System.out.println("PIN is incorrect");
        }
    }

    public void bad_case_12(HttpServletRequest request) {
        String expectedSignature = "abcdef123456";
        String providedSignature = request.getParameter("signature");
        
        // ruleid: java-unsecure-comparison
        boolean signatureValid = expectedSignature.equalsIgnoreCase(providedSignature);
        if (signatureValid) {
            System.out.println("Signature is valid");
        }
    }

    public void bad_case_13(HttpServletRequest request) {
        char[] secretChars = {'s', 'e', 'c', 'r', 'e', 't'};
        String userSecret = request.getParameter("secret");
        char[] userChars = userSecret.toCharArray();
        
        boolean isEqual = true;
        if (secretChars.length != userChars.length) {
            isEqual = false;
        } else {
            for (int i = 0; i < secretChars.length; i++) {
                // ruleid: java-unsecure-comparison
                if (secretChars[i] != userChars[i]) {
                    isEqual = false;
                    break;
                }
            }
        }
        
        if (isEqual) {
            System.out.println("Secret is valid");
        }
    }

    public void bad_case_14(HttpServletRequest request) {
        String storedToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String userToken = request.getHeader("Authorization");
        
        // ruleid: java-unsecure-comparison
        if (userToken != null && storedToken.equals(userToken)) {
            System.out.println("Token is valid");
        } else {
            System.out.println("Invalid token");
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        String correctAnswer = "secret_answer";
        String userAnswer = request.getParameter("security_answer");
        
        // ruleid: java-unsecure-comparison
        if (correctAnswer.toLowerCase().equals(userAnswer.toLowerCase())) {
            System.out.println("Security answer is correct");
        } else {
            System.out.println("Security answer is incorrect");
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1(HttpServletRequest request) {
        String storedApiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
        String userProvidedApiKey = request.getHeader("X-API-Key");
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(storedApiKey.getBytes(), userProvidedApiKey.getBytes())) {
            System.out.println("API key is valid");
        } else {
            System.out.println("API key is invalid");
        }
    }

    public void good_case_2(HttpServletRequest request) {
        String storedPassword = "supersecretpassword123";
        String userPassword = request.getParameter("password");
        
        // ok: java-unsecure-comparison
        if (userPassword != null && MessageDigest.isEqual(
                storedPassword.getBytes(StandardCharsets.UTF_8),
                userPassword.getBytes(StandardCharsets.UTF_8))) {
            System.out.println("Password is correct");
        } else {
            System.out.println("Password is incorrect");
        }
    }

    public void good_case_3(HttpServletRequest request) {
        byte[] storedToken = Base64.getDecoder().decode("c2VjcmV0dG9rZW4=");
        String userToken = request.getParameter("token");
        byte[] userTokenBytes = Base64.getDecoder().decode(userToken);
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(storedToken, userTokenBytes)) {
            System.out.println("Token is valid");
        }
    }

    @RestController
    public class good_case_4 {
        private final String JWT_SECRET = "jwt_secret_key_12345";
        
        @PostMapping("/verify")
        public String verifyToken(@RequestHeader("Authorization") String authHeader) {
            String token = authHeader.substring(7); // Remove "Bearer " prefix
            String signature = extractSignature(token);
            String expectedSignature = calculateSignature(token, JWT_SECRET);
            
            // ok: java-unsecure-comparison
            if (MessageDigest.isEqual(
                    signature.getBytes(StandardCharsets.UTF_8),
                    expectedSignature.getBytes(StandardCharsets.UTF_8))) {
                return "Token is valid";
            }
            return "Token is invalid";
        }
        
        private String extractSignature(String token) {
            String[] parts = token.split("\\.");
            return parts[2];
        }
        
        private String calculateSignature(String token, String secret) {
            // Simplified for example
            return "calculated_signature";
        }
    }

    public void good_case_5(HttpServletRequest request) {
        String storedHash = "5f4dcc3b5aa765d61d8327deb882cf99"; // MD5 hash of "password"
        String userPassword = request.getParameter("password");
        String userHash = getMD5Hash(userPassword);
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(
                storedHash.getBytes(StandardCharsets.UTF_8),
                userHash.getBytes(StandardCharsets.UTF_8))) {
            System.out.println("Password is correct");
        }
    }

    public void good_case_6(HttpServletRequest request) {
        String correctOTP = "123456";
        String userOTP = request.getParameter("otp");
        
        // ok: java-unsecure-comparison
        boolean isValid = MessageDigest.isEqual(
                correctOTP.getBytes(StandardCharsets.UTF_8),
                userOTP.getBytes(StandardCharsets.UTF_8));
        if (isValid) {
            System.out.println("OTP verification successful");
        }
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) {
        String storedCSRFToken = "random_csrf_token_value";
        String userCSRFToken = request.getParameter("csrf_token");
        
        // ok: java-unsecure-comparison
        if (!MessageDigest.isEqual(
                storedCSRFToken.getBytes(StandardCharsets.UTF_8),
                userCSRFToken.getBytes(StandardCharsets.UTF_8))) {
            response.setStatus(403);
            return;
        }
        
        System.out.println("CSRF token is valid");
    }

    @RestController
    public class good_case_8 {
        private final String API_SECRET = "api_secret_12345";
        
        @GetMapping("/webhook")
        public String handleWebhook(@RequestParam String payload, @RequestParam String signature) {
            String calculatedSignature = calculateHMAC_REDACTED_TWILIO_ID(payload, API_SECRET);
            
            // ok: java-unsecure-comparison
            if (MessageDigest.isEqual(
                    calculatedSignature.getBytes(StandardCharsets.UTF_8),
                    signature.getBytes(StandardCharsets.UTF_8))) {
                return "Webhook signature verified";
            }
            return "Invalid signature";
        }
        
        private String calculateHMAC_REDACTED_TWILIO_ID(String data, String key) {
            try {
                Mac sha256_HMAC_REDACTED_TWILIO_ID = Mac.getInstance("HmacSHA256");
                SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
                sha256_HMAC_REDACTED_TWILIO_ID.init(secret_key);
                return Base64.getEncoder().encodeToString(sha256_HMAC_REDACTED_TWILIO_ID.doFinal(data.getBytes("UTF-8")));
            } catch (Exception e) {
                return "";
            }
        }
    }

    public void good_case_9(HttpServletRequest request) {
        // Using BCrypt for password comparison which is timing-attack resistant
        String storedPasswordHash = "$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG";
        String userPassword = request.getParameter("password");
        
        // ok: java-unsecure-comparison
        if (BCrypt.checkpw(userPassword, storedPasswordHash)) {
            System.out.println("Password is correct");
        } else {
            System.out.println("Password is incorrect");
        }
    }

    public void good_case_10(HttpServletRequest request) {
        // Using a secure random token comparison
        String storedToken = "secure_token_value";
        String userToken = request.getParameter("token");
        
        // Constant time comparison implementation
        // ok: java-unsecure-comparison
        boolean isEqual = constantTimeEquals(storedToken, userToken);
        if (isEqual) {
            System.out.println("Token is valid");
        }
    }
    
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(aBytes, bBytes);
    }

    public void good_case_11(HttpServletRequest request) {
        // Using javax.crypto for MAC_REDACTED_TWILIO_ID comparison
        String key = "secret_key";
        String expectedMAC_REDACTED_TWILIO_ID = "expected_mac_value";
        String message = request.getParameter("message");
        String providedMAC_REDACTED_TWILIO_ID = request.getParameter("mac");
        
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
            mac.init(secretKey);
            byte[] rawHmac = mac.doFinal(message.getBytes());
            String calculatedMAC_REDACTED_TWILIO_ID = Base64.getEncoder().encodeToString(rawHmac);
            
            // ok: java-unsecure-comparison
            boolean macValid = MessageDigest.isEqual(
                    calculatedMAC_REDACTED_TWILIO_ID.getBytes(StandardCharsets.UTF_8),
                    providedMAC_REDACTED_TWILIO_ID.getBytes(StandardCharsets.UTF_8));
            
            if (macValid) {
                System.out.println("MAC_REDACTED_TWILIO_ID is valid");
            }
        } catch (Exception e) {
            System.out.println("Error validating MAC_REDACTED_TWILIO_ID");
        }
    }

    public void good_case_12(HttpServletRequest request) {
        // Non-secret comparison - not security sensitive
        String username = request.getParameter("username");
        String expectedUsername = "admin";
        
        // ok: java-unsecure-comparison
        if (username.equals(expectedUsername)) {
            System.out.println("Username is admin");
        }
    }

    public void good_case_13(HttpServletRequest request) {
        // Using a custom constant-time comparison method
        byte[] secretBytes = "secret_bytes_value".getBytes();
        String userInput = request.getParameter("secret");
        byte[] userBytes = userInput.getBytes();
        
        // ok: java-unsecure-comparison
        boolean isEqual = constantTimeCompare(secretBytes, userBytes);
        if (isEqual) {
            System.out.println("Secret is valid");
        }
    }
    
    private boolean constantTimeCompare(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    public void good_case_14(HttpServletRequest request) {
        // Using a secure random token generator and constant-time comparison
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String token = Base64.getEncoder().encodeToString(randomBytes);
        
        String userToken = request.getParameter("token");
        
        // ok: java-unsecure-comparison
        boolean isValid = MessageDigest.isEqual(
                token.getBytes(StandardCharsets.UTF_8),
                userToken.getBytes(StandardCharsets.UTF_8));
        
        if (isValid) {
            System.out.println("Token is valid");
        }
    }

    public void good_case_15(HttpServletRequest request) {
        // Comparing non-sensitive data (not a security issue)
        String expectedContentType = "application/json";
        String contentType = request.getContentType();
        
        // ok: java-unsecure-comparison
        if (expectedContentType.equals(contentType)) {
            System.out.println("Content type is JSON");
        }
    }
}
// {/fact}