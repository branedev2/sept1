package com.example.inputvalidation;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class InputValidationExamples {

    // True Positive Examples (Vulnerable)

// {fact rule=improper-input-validation@v1.0 defects=1}
    @GetMapping("/user/{id}")
    public void bad_case_1(@PathVariable String id, HttpServletResponse response) throws IOException {
        // ruleid: java-inputvalidation-v1
        // No validation of the id parameter
        response.getWriter().write("User ID: " + id);
    }

    @PostMapping("/process")
    public String bad_case_2(@RequestBody Map<String, Object> payload) {
        String username = (String) payload.get("username");
        // ruleid: java-inputvalidation-v1
        // No validation of username from request body
        return "Processing data for: " + username;
    }

    @GetMapping("/file")
    public byte[] bad_case_3(@RequestParam String filename) throws IOException {
        // ruleid: java-inputvalidation-v1
        // No validation of filename parameter
        File file = new File(filename);
        return Files.readAllBytes(file.toPath());
    }

    @GetMapping("/search")
    public List<String> bad_case_4(@RequestParam String query) {
        // ruleid: java-inputvalidation-v1
        // No validation of search query
        List<String> results = new ArrayList<>();
        results.add("Search results for: " + query);
        return results;
    }

    @PostMapping("/execute")
    public void bad_case_5(@RequestParam String command) throws IOException {
        // ruleid: java-inputvalidation-v1
        // No validation of command parameter
        Runtime.getRuntime().exec(command);
    }

    @GetMapping("/redirect")
    public void bad_case_6(@RequestParam String url, HttpServletResponse response) throws IOException {
        // ruleid: java-inputvalidation-v1
        // No validation of URL parameter
        response.sendRedirect(url);
    }

    @GetMapping("/query")
    public void bad_case_7(@RequestParam String sqlQuery, HttpServletResponse response) throws SQLException {
        // ruleid: java-inputvalidation-v1
        // No validation of SQL query parameter
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "user", "password");
        Statement stmt = conn.createStatement();
        stmt.execute(sqlQuery);
    }

    @GetMapping("/age")
    public String bad_case_8(@RequestParam String age) {
        // ruleid: java-inputvalidation-v1
        // No validation of age parameter
        int userAge = Integer.parseInt(age);
        return "User age: " + userAge;
    }

    @PostMapping("/register")
    public String bad_case_9(@RequestParam String email) {
        // ruleid: java-inputvalidation-v1
        // No validation of email parameter
        return "Registered with email: " + email;
    }

    @GetMapping("/data")
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String type = request.getParameter("type");
        // ruleid: java-inputvalidation-v1
        // No validation of type parameter
        response.getWriter().write("Data type: " + type);
    }

    public void bad_case_11(String path) throws IOException {
        // ruleid: java-inputvalidation-v1
        // Public method with no parameter validation
        Files.readAllBytes(Paths.get(path));
    }

    public int bad_case_12(String number) {
        // ruleid: java-inputvalidation-v1
        // Public method with no parameter validation
        return Integer.parseInt(number);
    }

    public void bad_case_13(String username, String password) {
        // ruleid: java-inputvalidation-v1
        // Public method with no parameter validation
        System.out.println("Authenticating user: " + username + " with password: " + password);
    }

    public File bad_case_14(String directoryPath, String fileName) {
        // ruleid: java-inputvalidation-v1
        // Public method with no parameter validation
        return new File(directoryPath, fileName);
    }

    public void bad_case_15(List<String> commands) throws IOException {
        // ruleid: java-inputvalidation-v1
        // Public method with no parameter validation
        for (String cmd : commands) {
            Runtime.getRuntime().exec(cmd);
        }
    }

    // True Negative Examples (Secure)

    @GetMapping("/user-safe/{id}")
    public void good_case_1(@PathVariable String id, HttpServletResponse response) throws IOException {
        // ok: java-inputvalidation-v1
        if (id == null || !id.matches("^[0-9]+$")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid user ID");
            return;
        }
        response.getWriter().write("User ID: " + id);
    }

    @PostMapping("/process-safe")
    public String good_case_2(@RequestBody Map<String, Object> payload) {
        String username = (String) payload.get("username");
        // ok: java-inputvalidation-v1
        if (username == null || username.isEmpty() || username.length() > 50 || !username.matches("^[a-zA-Z0-9_]+$")) {
            return "Invalid username";
        }
        return "Processing data for: " + username;
    }

    @GetMapping("/file-safe")
    public byte[] good_case_3(@RequestParam String filename) throws IOException {
        // ok: java-inputvalidation-v1
        if (filename == null || filename.contains("..") || !filename.matches("^[a-zA-Z0-9_\\-\\.]+$")) {
            throw new IllegalArgumentException("Invalid filename");
        }
        File file = new File("safe_directory/" + filename);
        return Files.readAllBytes(file.toPath());
    }

    @GetMapping("/search-safe")
    public List<String> good_case_4(@RequestParam String query) {
        // ok: java-inputvalidation-v1
        if (query == null || query.isEmpty() || query.length() > 100) {
            throw new IllegalArgumentException("Invalid search query");
        }
        List<String> results = new ArrayList<>();
        results.add("Search results for: " + query);
        return results;
    }

    @PostMapping("/execute-safe")
    public void good_case_5(@RequestParam String command) throws IOException {
        // ok: java-inputvalidation-v1
        List<String> allowedCommands = List.of("status", "version", "help");
        if (command == null || !allowedCommands.contains(command)) {
            throw new IllegalArgumentException("Invalid command");
        }
        Runtime.getRuntime().exec("safe_script.sh " + command);
    }

    @GetMapping("/redirect-safe")
    public void good_case_6(@RequestParam String url, HttpServletResponse response) throws IOException {
        // ok: java-inputvalidation-v1
        if (url == null || !url.startsWith("https://trusted-domain.com/")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid redirect URL");
            return;
        }
        response.sendRedirect(url);
    }

    @GetMapping("/query-safe")
    public void good_case_7(@RequestParam String table, HttpServletResponse response) throws SQLException {
        // ok: java-inputvalidation-v1
        List<String> allowedTables = List.of("users", "products", "orders");
        if (table == null || !allowedTables.contains(table.toLowerCase())) {
            throw new IllegalArgumentException("Invalid table name");
        }
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "user", "password");
        Statement stmt = conn.createStatement();
        stmt.execute("SELECT * FROM " + table + " LIMIT 10");
    }

    @GetMapping("/age-safe")
    public String good_case_8(@RequestParam String age) {
        // ok: java-inputvalidation-v1
        if (age == null || !age.matches("^[0-9]+$")) {
            return "Invalid age format";
        }
        int userAge = Integer.parseInt(age);
        if (userAge < 0 || userAge > 120) {
            return "Age out of valid range";
        }
        return "User age: " + userAge;
    }

    @PostMapping("/register-safe")
    public String good_case_9(@RequestParam String email) {
        // ok: java-inputvalidation-v1
        if (email == null || !Pattern.matches("^[A-Za-z0-9+_.-]+@(.+)$", email)) {
            return "Invalid email format";
        }
        return "Registered with email: " + email;
    }

    @GetMapping("/data-safe")
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String type = request.getParameter("type");
        // ok: java-inputvalidation-v1
        List<String> validTypes = List.of("json", "xml", "csv");
        if (type == null || !validTypes.contains(type.toLowerCase())) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid data type");
            return;
        }
        response.getWriter().write("Data type: " + type);
    }

    public void good_case_11(String path) throws IOException {
        // ok: java-inputvalidation-v1
        Objects.requireNonNull(path, "Path cannot be null");
        if (path.contains("..") || !path.startsWith("/safe/")) {
            throw new IllegalArgumentException("Invalid path");
        }
        Files.readAllBytes(Paths.get(path));
    }

    public int good_case_12(String number) {
        // ok: java-inputvalidation-v1
        if (number == null || !number.matches("^-?[0-9]+$")) {
            throw new IllegalArgumentException("Invalid number format");
        }
        return Integer.parseInt(number);
    }

    public void good_case_13(String username, String password) {
        // ok: java-inputvalidation-v1
        if (username == null || username.isEmpty() || username.length() > 50) {
            throw new IllegalArgumentException("Invalid username");
        }
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException("Invalid password");
        }
        System.out.println("Authenticating user: " + username);
    }

    public File good_case_14(String directoryPath, String fileName) {
        // ok: java-inputvalidation-v1
        if (directoryPath == null || !directoryPath.startsWith("/allowed/")) {
            throw new IllegalArgumentException("Invalid directory path");
        }
        if (fileName == null || fileName.contains("/") || fileName.contains("\\")) {
            throw new IllegalArgumentException("Invalid file name");
        }
        return new File(directoryPath, fileName);
    }

    public void good_case_15(List<String> commands) throws IOException {
        // ok: java-inputvalidation-v1
        if (commands == null || commands.isEmpty()) {
            throw new IllegalArgumentException("Commands list cannot be null or empty");
        }
        List<String> allowedCommands = List.of("status", "version", "help");
        for (String cmd : commands) {
            if (!allowedCommands.contains(cmd)) {
                throw new IllegalArgumentException("Invalid command: " + cmd);
            }
            Runtime.getRuntime().exec("safe_script.sh " + cmd);
        }
    }
}
// {/fact}