import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Scanner;
import java.io.File;
import java.util.Properties;
import java.util.ArrayList;
import java.util.List;

public class StringComparisonExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=string-equality-check@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String storedUsername = "admin";
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (username == storedUsername && password.equals("admin123")) {
            response.getWriter().write("Login successful");
        } else {
            response.getWriter().write("Login failed");
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        String role = request.getParameter("role");
        String adminRole = "admin";
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (role == adminRole) {
            System.out.println("User is an admin");
        } else {
            System.out.println("User is not an admin");
        }
    }

    public void bad_case_3(HttpServletRequest request) {
        String action = request.getParameter("action");
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (action == "delete") {
            System.out.println("Deleting records...");
        }
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String token = request.getHeader("Authorization");
        String validToken = "Bearer 12345";
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (token == validToken) {
            response.getWriter().write("Access granted");
        } else {
            response.getWriter().write("Access denied");
        }
    }

    public void bad_case_5() throws IOException {
        Properties props = new Properties();
        props.load(getClass().getResourceAsStream("/config.properties"));
        String environment = props.getProperty("environment");
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (environment == "production") {
            System.out.println("Running in production mode");
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        String userInput = request.getParameter("command");
        String dangerousCommand = "DROP_TABLE";
        
        // ruleid: java-equals-operator-vs-is-equal-method
        boolean isDangerous = (userInput == dangerousCommand);
        if (isDangerous) {
            System.out.println("Dangerous command detected");
        }
    }

    public void bad_case_7(HttpServletRequest request, HttpSession session) {
        String sessionId = request.getParameter("sessionId");
        String storedSessionId = (String) session.getAttribute("sessionId");
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (sessionId == storedSessionId) {
            System.out.println("Session validated");
        } else {
            System.out.println("Invalid session");
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        Map<String, String> allowedOperations = new HashMap<>();
        allowedOperations.put("user", "read");
        
        String userRole = request.getParameter("role");
        String operation = request.getParameter("operation");
        String allowedOperation = allowedOperations.get(userRole);
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (operation == allowedOperation) {
            System.out.println("Operation allowed");
        } else {
            System.out.println("Operation not allowed");
        }
    }

    public void bad_case_9() throws Exception {
        Scanner scanner = new Scanner(new File("users.txt"));
        String line = scanner.nextLine();
        String targetUser = "admin";
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (line == targetUser) {
            System.out.println("Found admin user");
        }
        scanner.close();
    }

    public void bad_case_10(HttpServletRequest request) {
        String contentType = request.getHeader("Content-Type");
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (contentType == "application/json") {
            System.out.println("Processing JSON request");
        } else {
            System.out.println("Unsupported content type");
        }
    }

    public void bad_case_11(HttpServletRequest request) {
        String method = request.getMethod();
        
        // ruleid: java-equals-operator-vs-is-equal-method
        if (method == "POST") {
            System.out.println("Processing POST request");
        }
    }

    public void bad_case_12(HttpServletRequest request) {
        String[] allowedDomains = {"example.com", "trusted.org"};
        String referer = request.getHeader("Referer");
        boolean isAllowed = false;
        
        for (String domain : allowedDomains) {
            // ruleid: java-equals-operator-vs-is-equal-method
            if (referer == domain) {
                isAllowed = true;
                break;
            }
        }
    }

    public void bad_case_13(HttpServletRequest request) {
        List<String> users = new ArrayList<>();
        users.add("admin");
        users.add("user");
        
        String username = request.getParameter("username");
        boolean userExists = false;
        
        for (String user : users) {
            // ruleid: java-equals-operator-vs-is-equal-method
            if (username == user) {
                userExists = true;
                break;
            }
        }
    }

    public void bad_case_14(HttpServletRequest request) {
        String lang = request.getParameter("lang");
        String defaultLang = "en";
        
        // ruleid: java-equals-operator-vs-is-equal-method
        String language = (lang == null || lang == "") ? defaultLang : lang;
        System.out.println("Using language: " + language);
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getParameter("action");
        String result;
        
        // ruleid: java-equals-operator-vs-is-equal-method
        switch (action) {
            case "view":
                result = "Viewing records";
                break;
            case "edit":
                result = "Editing records";
                break;
            default:
                result = "Unknown action";
        }
        
        response.getWriter().write(result);
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String storedUsername = "admin";
        
        // ok: java-equals-operator-vs-is-equal-method
        if (storedUsername.equals(username) && password.equals("admin123")) {
            response.getWriter().write("Login successful");
        } else {
            response.getWriter().write("Login failed");
        }
    }

    public void good_case_2(HttpServletRequest request) {
        String role = request.getParameter("role");
        String adminRole = "admin";
        
        // ok: java-equals-operator-vs-is-equal-method
        if (adminRole.equals(role)) {
            System.out.println("User is an admin");
        } else {
            System.out.println("User is not an admin");
        }
    }

    public void good_case_3(HttpServletRequest request) {
        String action = request.getParameter("action");
        
        // ok: java-equals-operator-vs-is-equal-method
        if ("delete".equals(action)) {
            System.out.println("Deleting records...");
        }
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String token = request.getHeader("Authorization");
        String validToken = "Bearer 12345";
        
        // ok: java-equals-operator-vs-is-equal-method
        if (validToken.equals(token)) {
            response.getWriter().write("Access granted");
        } else {
            response.getWriter().write("Access denied");
        }
    }

    public void good_case_5() throws IOException {
        Properties props = new Properties();
        props.load(getClass().getResourceAsStream("/config.properties"));
        String environment = props.getProperty("environment");
        
        // ok: java-equals-operator-vs-is-equal-method
        if ("production".equals(environment)) {
            System.out.println("Running in production mode");
        }
    }

    public void good_case_6(HttpServletRequest request) {
        String userInput = request.getParameter("command");
        String dangerousCommand = "DROP_TABLE";
        
        // ok: java-equals-operator-vs-is-equal-method
        boolean isDangerous = dangerousCommand.equals(userInput);
        if (isDangerous) {
            System.out.println("Dangerous command detected");
        }
    }

    public void good_case_7(HttpServletRequest request, HttpSession session) {
        String sessionId = request.getParameter("sessionId");
        String storedSessionId = (String) session.getAttribute("sessionId");
        
        // ok: java-equals-operator-vs-is-equal-method
        if (storedSessionId != null && storedSessionId.equals(sessionId)) {
            System.out.println("Session validated");
        } else {
            System.out.println("Invalid session");
        }
    }

    public void good_case_8(HttpServletRequest request) {
        Map<String, String> allowedOperations = new HashMap<>();
        allowedOperations.put("user", "read");
        
        String userRole = request.getParameter("role");
        String operation = request.getParameter("operation");
        String allowedOperation = allowedOperations.get(userRole);
        
        // ok: java-equals-operator-vs-is-equal-method
        if (allowedOperation != null && allowedOperation.equals(operation)) {
            System.out.println("Operation allowed");
        } else {
            System.out.println("Operation not allowed");
        }
    }

    public void good_case_9() throws Exception {
        Scanner scanner = new Scanner(new File("users.txt"));
        String line = scanner.nextLine();
        String targetUser = "admin";
        
        // ok: java-equals-operator-vs-is-equal-method
        if (targetUser.equals(line)) {
            System.out.println("Found admin user");
        }
        scanner.close();
    }

    public void good_case_10(HttpServletRequest request) {
        String contentType = request.getHeader("Content-Type");
        
        // ok: java-equals-operator-vs-is-equal-method
        if ("application/json".equals(contentType)) {
            System.out.println("Processing JSON request");
        } else {
            System.out.println("Unsupported content type");
        }
    }

    public void good_case_11(HttpServletRequest request) {
        String method = request.getMethod();
        
        // ok: java-equals-operator-vs-is-equal-method
        if ("POST".equals(method)) {
            System.out.println("Processing POST request");
        }
    }

    public void good_case_12(HttpServletRequest request) {
        String[] allowedDomains = {"example.com", "trusted.org"};
        String referer = request.getHeader("Referer");
        boolean isAllowed = false;
        
        for (String domain : allowedDomains) {
            // ok: java-equals-operator-vs-is-equal-method
            if (domain.equals(referer)) {
                isAllowed = true;
                break;
            }
        }
    }

    public void good_case_13(HttpServletRequest request) {
        List<String> users = new ArrayList<>();
        users.add("admin");
        users.add("user");
        
        String username = request.getParameter("username");
        boolean userExists = false;
        
        // ok: java-equals-operator-vs-is-equal-method
        userExists = users.contains(username);
    }

    public void good_case_14(HttpServletRequest request) {
        String lang = request.getParameter("lang");
        String defaultLang = "en";
        
        // ok: java-equals-operator-vs-is-equal-method
        String language = (lang == null || lang.isEmpty()) ? defaultLang : lang;
        System.out.println("Using language: " + language);
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getParameter("action");
        String result;
        
        // Using equals for string comparison in conditional statements
        // ok: java-equals-operator-vs-is-equal-method
        if ("view".equals(action)) {
            result = "Viewing records";
        } else if ("edit".equals(action)) {
            result = "Editing records";
        } else {
            result = "Unknown action";
        }
        
        response.getWriter().write(result);
    }
}
// {/fact}