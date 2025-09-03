import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;

public class StringNullComparisonExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=inconsistent-null-check@v1.0 defects=1}
    public void bad_case_1(String userInput) {
        // Direct comparison with null using equals
        if (userInput.equals(null)) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("This will never be true and might throw NPE");
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        String username = request.getParameter("username");
        // Potential NPE if username is null
        if (username.equals("admin")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Admin logged in");
        }
    }

    public void bad_case_3() {
        Map<String, String> userMap = new HashMap<>();
        String userId = userMap.get("id"); // Could be null if key doesn't exist
        
        // Potential NPE if userId is null
        if (userId.equals("12345")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("User found");
        }
    }

    public void bad_case_4(Properties props) {
        String configValue = props.getProperty("database.url");
        
        // Potential NPE if configValue is null
        if (configValue.equals("jdbc:mysql://localhost:3306/mydb")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Using local database");
        }
    }

    public void bad_case_5(HttpServletRequest request) {
        String action = request.getParameter("action");
        String target = null;
        
        // Will throw NPE when action is null
        if (action.equals("delete")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            target = "user";
        }
        
        System.out.println("Target: " + target);
    }

    public void bad_case_6(List<String> dataList) {
        String item = dataList.isEmpty() ? null : dataList.get(0);
        
        // Potential NPE if list was empty
        if (item.equals("start")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Starting process");
        }
    }

    public void bad_case_7(Map<String, Object> sessionData) {
        String token = (String) sessionData.get("auth_token");
        
        // Potential NPE if token is null
        if (token.equals("expired")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Token has expired");
        }
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("redirect");
        
        // Potential NPE if redirectUrl is null
        if (redirectUrl.equals("/home")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            response.sendRedirect("/dashboard");
        } else {
            response.sendRedirect(redirectUrl);
        }
    }

    public void bad_case_9() {
        String[] parts = "some:string".split(":");
        String secondPart = parts.length > 1 ? parts[1] : null;
        
        // Potential NPE if secondPart is null
        if (secondPart.equals("string")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Found expected value");
        }
    }

    public void bad_case_10(Optional<String> optionalValue) {
        String value = optionalValue.orElse(null);
        
        // Potential NPE if value is null
        if (value.equals("expected")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Value matches expected");
        }
    }

    public void bad_case_11(HttpServletRequest request) {
        String method = request.getMethod();
        String contentType = request.getContentType(); // Could be null
        
        // Potential NPE if contentType is null
        if (contentType.equals("application/json")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Processing JSON request");
        }
    }

    public void bad_case_12(Map<String, String> config) {
        String environment = config.get("ENV");
        
        // Potential NPE if environment is null
        if (environment.equals("production")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Running in production mode");
        }
    }

    public void bad_case_13(String[] args) {
        String flag = args.length > 0 ? args[0] : null;
        
        // Potential NPE if flag is null
        if (flag.equals("--debug")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Debug mode enabled");
        }
    }

    public void bad_case_14(HttpServletRequest request) {
        String sessionId = request.getParameter("sessionId");
        String userId = null;
        
        // Multiple potential NPEs in one method
        if (sessionId.equals("expired")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            userId = request.getParameter("userId");
            
            if (userId.equals("admin")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
                System.out.println("Admin session expired");
            }
        }
    }

    public void bad_case_15(Properties systemProps) {
        String osName = systemProps.getProperty("unknown.property");
        
        // Potential NPE if property doesn't exist
        if (osName.equals("Linux")) { // ruleid: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Running on Linux");
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(String userInput) {
        // Safe comparison with null using equals
        if ("admin".equals(userInput)) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Admin logged in");
        }
    }

    public void good_case_2(HttpServletRequest request) {
        String username = request.getParameter("username");
        // Safe comparison with constant on left side
        if ("admin".equals(username)) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Admin logged in");
        }
    }

    public void good_case_3() {
        Map<String, String> userMap = new HashMap<>();
        String userId = userMap.get("id"); // Could be null
        
        // Safe null check before equals
        if (userId != null && userId.equals("12345")) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("User found");
        }
    }

    public void good_case_4(Properties props) {
        String configValue = props.getProperty("database.url");
        
        // Safe comparison with constant string on left
        if ("jdbc:mysql://localhost:3306/mydb".equals(configValue)) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Using local database");
        }
    }

    public void good_case_5(HttpServletRequest request) {
        String action = request.getParameter("action");
        String target = null;
        
        // Safe null check before using equals
        if (action != null && action.equals("delete")) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            target = "user";
        }
        
        System.out.println("Target: " + target);
    }

    public void good_case_6(List<String> dataList) {
        if (!dataList.isEmpty()) {
            String item = dataList.get(0);
            // Safe because we checked the list is not empty
            if ("start".equals(item)) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
                System.out.println("Starting process");
            }
        }
    }

    public void good_case_7(Map<String, Object> sessionData) {
        String token = (String) sessionData.get("auth_token");
        
        // Safe comparison with constant on left
        if ("expired".equals(token)) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Token has expired");
        }
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("redirect");
        
        // Safe null check and comparison
        if (redirectUrl != null && redirectUrl.equals("/home")) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            response.sendRedirect("/dashboard");
        } else if (redirectUrl != null) {
            response.sendRedirect(redirectUrl);
        } else {
            response.sendRedirect("/default");
        }
    }

    public void good_case_9() {
        String[] parts = "some:string".split(":");
        
        // Safe check for array length and comparison
        if (parts.length > 1 && "string".equals(parts[1])) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Found expected value");
        }
    }

    public void good_case_10(Optional<String> optionalValue) {
        // Safe use of Optional
        if (optionalValue.isPresent() && "expected".equals(optionalValue.get())) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Value matches expected");
        }
    }

    public void good_case_11(HttpServletRequest request) {
        String contentType = request.getContentType(); // Could be null
        
        // Safe comparison with constant on left
        if ("application/json".equals(contentType)) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Processing JSON request");
        }
    }

    public void good_case_12(Map<String, String> config) {
        String environment = config.getOrDefault("ENV", "development");
        
        // Safe because getOrDefault ensures non-null
        if (environment.equals("production")) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Running in production mode");
        }
    }

    public void good_case_13(String[] args) {
        // Safe check with default value
        String flag = args.length > 0 ? args[0] : "";
        
        // Safe because flag is never null
        if (flag.equals("--debug")) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Debug mode enabled");
        }
    }

    public void good_case_14(HttpServletRequest request) {
        String sessionId = request.getParameter("sessionId");
        
        // Using Objects.equals for safe comparison
        if (java.util.Objects.equals(sessionId, "expired")) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            String userId = request.getParameter("userId");
            if (java.util.Objects.equals(userId, "admin")) {
                System.out.println("Admin session expired");
            }
        }
    }

    public void good_case_15(String input) {
        // Using String.valueOf to ensure non-null
        String safeInput = String.valueOf(input);
        
        // Safe because String.valueOf never returns null
        if (safeInput.equals("test")) { // ok: java-avoid-invoking-string-comparison-method-with-null-string
            System.out.println("Input is test");
        }
    }
}
// {/fact}