import org.springframework.util.Base64Utils;
import org.springframework.security.crypto.codec.Base64;
import java.util.Base64;
import org.apache.commons.codec.binary.Base64;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
public class Base64UsageExamples {

    // True Positives (Vulnerable Code - Using deprecated Spring Base64)

// {fact rule=deprecated-method@v1.0 defects=1}
    public void bad_case_1() {
        String data = "Hello World";
        // ruleid: java-deprecatedspringbase64
        byte[] encodedBytes = Base64.encode(data.getBytes());
        System.out.println("Encoded data: " + new String(encodedBytes));
    }

    @GetMapping("/encode-bad-2")
    public String bad_case_2(@RequestParam String input) {
        // ruleid: java-deprecatedspringbase64
        byte[] encodedBytes = Base64.encode(input.getBytes(StandardCharsets.UTF_8));
        return new String(encodedBytes);
    }

    @PostMapping("/decode-bad-3")
    public ResponseEntity<String> bad_case_3(@RequestBody String encodedData) {
        try {
            // ruleid: java-deprecatedspringbase64
            byte[] decodedBytes = Base64.decode(encodedData.getBytes());
            String decodedString = new String(decodedBytes, StandardCharsets.UTF_8);
            return ResponseEntity.ok(decodedString);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid Base64 input");
        }
    }

    public void bad_case_4() {
        String username = "admin";
        String password = "password123";
        String credentials = username + ":" + password;
        
        // ruleid: java-deprecatedspringbase64
        String basicAuth = new String(Base64.encode(credentials.getBytes()));
        System.out.println("Authorization: Basic " + basicAuth);
    }

    @Service
    public class TokenService {
        public String bad_case_5(String token) {
            // ruleid: java-deprecatedspringbase64
            byte[] decodedToken = Base64.decode(token.getBytes());
            return new String(decodedToken);
        }
    }

    public void bad_case_6() {
        String secretKey = "mySecretKey";
        // ruleid: java-deprecatedspringbase64
        byte[] encodedKey = Base64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
        System.out.println("Encoded key: " + new String(encodedKey));
    }

    @GetMapping("/encrypt")
    public String bad_case_7(@RequestParam String plainText) {
        // ruleid: java-deprecatedspringbase64
        String encoded = new String(Base64.encode(plainText.getBytes()));
        return encoded;
    }

    public void bad_case_8() {
        String imageData = "image binary data";
        // ruleid: java-deprecatedspringbase64
        byte[] encodedImage = Base64.encode(imageData.getBytes());
        String base64Image = "data:image/jpeg;base64," + new String(encodedImage);
        System.out.println(base64Image);
    }

    public void bad_case_9() {
        String jwt = "header.payload.signature";
        String[] parts = jwt.split("\\.");
        
        for (String part : parts) {
            // ruleid: java-deprecatedspringbase64
            byte[] decoded = Base64.decode(part.getBytes());
            System.out.println(new String(decoded));
        }
    }

    public void bad_case_10() {
        String data = "test data";
        // ruleid: java-deprecatedspringbase64
        byte[] encoded = Base64.encode(data.getBytes());
        // ruleid: java-deprecatedspringbase64
        byte[] decoded = Base64.decode(encoded);
        System.out.println(new String(decoded));
    }

    @PostMapping("/process-credentials")
    public void bad_case_11(@RequestParam String encodedCredentials) {
        try {
            // ruleid: java-deprecatedspringbase64
            byte[] decodedBytes = Base64.decode(encodedCredentials.getBytes());
            String decodedCredentials = new String(decodedBytes);
            String[] parts = decodedCredentials.split(":");
            authenticateUser(parts[0], parts[1]);
        } catch (Exception e) {
            System.err.println("Error processing credentials");
        }
    }
    
    private void authenticateUser(String username, String password) {
        // Authentication logic
    }

    public String bad_case_12(byte[] binaryData) {
        // ruleid: java-deprecatedspringbase64
        return new String(Base64.encode(binaryData));
    }

    public void bad_case_13() {
        String url = "https://example.com/path?param=value";
        // ruleid: java-deprecatedspringbase64
        String encodedUrl = new String(Base64.encode(url.getBytes()));
        System.out.println("Encoded URL: " + encodedUrl);
    }

    public void bad_case_14() {
        String xml = "<root><child>value</child></root>";
        // ruleid: java-deprecatedspringbase64
        byte[] encodedXml = Base64.encode(xml.getBytes());
        System.out.println("Encoded XML: " + new String(encodedXml));
    }

    public void bad_case_15() {
        for (int i = 0; i < 5; i++) {
            String data = "data" + i;
            // ruleid: java-deprecatedspringbase64
            byte[] encoded = Base64.encode(data.getBytes());
            System.out.println("Encoded data " + i + ": " + new String(encoded));
        }
    }

    // True Negatives (Safe Code - Using non-deprecated Base64 alternatives)

    public void good_case_1() {
        String data = "Hello World";
        // ok: java-deprecatedspringbase64
        byte[] encodedBytes = Base64Utils.encode(data.getBytes());
        System.out.println("Encoded data: " + new String(encodedBytes));
    }

    @GetMapping("/encode-good-2")
    public String good_case_2(@RequestParam String input) {
        // ok: java-deprecatedspringbase64
        byte[] encodedBytes = Base64Utils.encode(input.getBytes(StandardCharsets.UTF_8));
        return new String(encodedBytes);
    }

    @PostMapping("/decode-good-3")
    public ResponseEntity<String> good_case_3(@RequestBody String encodedData) {
        try {
            // ok: java-deprecatedspringbase64
            byte[] decodedBytes = Base64Utils.decode(encodedData.getBytes());
            String decodedString = new String(decodedBytes, StandardCharsets.UTF_8);
            return ResponseEntity.ok(decodedString);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid Base64 input");
        }
    }

    public void good_case_4() {
        String username = "admin";
        String password = "password123";
        String credentials = username + ":" + password;
        
        // ok: java-deprecatedspringbase64
        String basicAuth = java.util.Base64.getEncoder().encodeToString(credentials.getBytes());
        System.out.println("Authorization: Basic " + basicAuth);
    }

    @Service
    public class ModernTokenService {
        public String good_case_5(String token) {
            // ok: java-deprecatedspringbase64
            byte[] decodedToken = java.util.Base64.getDecoder().decode(token);
            return new String(decodedToken);
        }
    }

    public void good_case_6() {
        String secretKey = "mySecretKey";
        // ok: java-deprecatedspringbase64
        String encodedKey = java.util.Base64.getEncoder().encodeToString(secretKey.getBytes(StandardCharsets.UTF_8));
        System.out.println("Encoded key: " + encodedKey);
    }

    @GetMapping("/encrypt-modern")
    public String good_case_7(@RequestParam String plainText) {
        // ok: java-deprecatedspringbase64
        String encoded = java.util.Base64.getEncoder().encodeToString(plainText.getBytes());
        return encoded;
    }

    public void good_case_8() {
        String imageData = "image binary data";
        // ok: java-deprecatedspringbase64
        String base64Image = "data:image/jpeg;base64," + 
            java.util.Base64.getEncoder().encodeToString(imageData.getBytes());
        System.out.println(base64Image);
    }

    public void good_case_9() {
        String jwt = "header.payload.signature";
        String[] parts = jwt.split("\\.");
        
        for (String part : parts) {
            // ok: java-deprecatedspringbase64
            byte[] decoded = java.util.Base64.getUrlDecoder().decode(part);
            System.out.println(new String(decoded));
        }
    }

    public void good_case_10() {
        String data = "test data";
        // ok: java-deprecatedspringbase64
        String encoded = org.apache.commons.codec.binary.Base64.encodeBase64String(data.getBytes());
        // ok: java-deprecatedspringbase64
        byte[] decoded = org.apache.commons.codec.binary.Base64.decodeBase64(encoded);
        System.out.println(new String(decoded));
    }

    @PostMapping("/process-credentials-safe")
    public void good_case_11(@RequestParam String encodedCredentials) {
        try {
            // ok: java-deprecatedspringbase64
            byte[] decodedBytes = java.util.Base64.getDecoder().decode(encodedCredentials);
            String decodedCredentials = new String(decodedBytes);
            String[] parts = decodedCredentials.split(":");
            authenticateUser(parts[0], parts[1]);
        } catch (Exception e) {
            System.err.println("Error processing credentials");
        }
    }

    public String good_case_12(byte[] binaryData) {
        // ok: java-deprecatedspringbase64
        return Base64Utils.encodeToString(binaryData);
    }

    public void good_case_13() {
        String url = "https://example.com/path?param=value";
        // ok: java-deprecatedspringbase64
        String encodedUrl = java.util.Base64.getUrlEncoder().encodeToString(url.getBytes());
        System.out.println("Encoded URL: " + encodedUrl);
    }

    public void good_case_14() {
        String xml = "<root><child>value</child></root>";
        // ok: java-deprecatedspringbase64
        String encodedXml = java.util.Base64.getMimeEncoder().encodeToString(xml.getBytes());
        System.out.println("Encoded XML: " + encodedXml);
    }

    public void good_case_15() {
        for (int i = 0; i < 5; i++) {
            String data = "data" + i;
            // ok: java-deprecatedspringbase64
            String encoded = Base64Utils.encodeToString(data.getBytes());
            System.out.println("Encoded data " + i + ": " + encoded);
        }
    }
}
// {/fact}