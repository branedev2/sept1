import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class ReturnElementInsideLoopExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=resource-leak@v1.0 defects=1}
    public String bad_case_1(List<User> users, String targetUsername) {
        for (User user : users) {
            if (user.getUsername().equals(targetUsername)) {
                // ruleid: java-return-element-inside-loop
                return user.getAuthToken(); // Returns first matching token without checking for duplicates
            }
        }
        return null;
    }

    public File bad_case_2(List<String> filePaths) {
        for (String path : filePaths) {
            File file = new File(path);
            if (file.exists() && file.canRead()) {
                // ruleid: java-return-element-inside-loop
                return file; // Returns first readable file without checking others
            }
        }
        return null;
    }

    public User bad_case_3(Map<Integer, User> userMap, String role) {
        for (User user : userMap.values()) {
            if (user.getRole().equals(role)) {
                // ruleid: java-return-element-inside-loop
                return user; // Returns first user with matching role
            }
        }
        return null;
    }

    public Connection bad_case_4(List<DatabaseConfig> configs) {
        for (DatabaseConfig config : configs) {
            try {
                Connection conn = DriverManager.getConnection(
                    config.getUrl(), config.getUsername(), config.getPassword());
                if (conn != null && !conn.isClosed()) {
                    // ruleid: java-return-element-inside-loop
                    return conn; // Returns first successful connection without checking others
                }
            } catch (SQLException e) {
                // Continue to next config
            }
        }
        return null;
    }

    public String bad_case_5(HttpServletRequest request) {
        String[] allowedRoles = request.getParameterValues("role");
        String userRole = request.getParameter("userRole");
        
        for (String role : allowedRoles) {
            if (role.equalsIgnoreCase(userRole)) {
                // ruleid: java-return-element-inside-loop
                return role; // Returns first matching role without checking for case-sensitive duplicates
            }
        }
        return null;
    }

    public Integer bad_case_6(int[] numbers, int threshold) {
        for (int i = 0; i < numbers.length; i++) {
            if (numbers[i] > threshold) {
                // ruleid: java-return-element-inside-loop
                return numbers[i]; // Returns first number above threshold
            }
        }
        return null;
    }

    public String bad_case_7(List<String> permissions, String userId) {
        for (String permission : permissions) {
            if (permission.startsWith(userId + ":")) {
                // ruleid: java-return-element-inside-loop
                return permission.substring(userId.length() + 1); // Returns first permission without checking others
            }
        }
        return null;
    }

    public String bad_case_8(Map<String, List<String>> resourceMap, String resourceType) {
        for (Map.Entry<String, List<String>> entry : resourceMap.entrySet()) {
            List<String> resources = entry.getValue();
            for (String resource : resources) {
                if (resource.contains(resourceType)) {
                    // ruleid: java-return-element-inside-loop
                    return resource; // Returns first matching resource in nested loops
                }
            }
        }
        return null;
    }

    public String bad_case_9(String[] lines, String searchTerm) {
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].contains(searchTerm)) {
                // ruleid: java-return-element-inside-loop
                return lines[i]; // Returns first line containing search term
            }
        }
        return null;
    }

    public File bad_case_10(String directory, String fileExtension) {
        File dir = new File(directory);
        File[] files = dir.listFiles();
        
        if (files != null) {
            for (File file : files) {
                if (file.getName().endsWith(fileExtension)) {
                    // ruleid: java-return-element-inside-loop
                    return file; // Returns first file with matching extension
                }
            }
        }
        return null;
    }

    public String bad_case_11(ResultSet resultSet) throws SQLException {
        while (resultSet.next()) {
            String status = resultSet.getString("status");
            if ("AC_REDACTED_TWILIO_ID".equals(status)) {
                // ruleid: java-return-element-inside-loop
                return resultSet.getString("id"); // Returns first active record ID
            }
        }
        return null;
    }

    public Integer bad_case_12(List<Transaction> transactions, String accountId) {
        for (Transaction transaction : transactions) {
            if (transaction.getAccountId().equals(accountId) && transaction.getAmount() > 1000) {
                // ruleid: java-return-element-inside-loop
                return transaction.getId(); // Returns first large transaction without checking others
            }
        }
        return null;
    }

    public String bad_case_13(HttpServletRequest request) {
        String[] cookies = request.getParameterValues("cookies");
        
        for (String cookie : cookies) {
            if (cookie.startsWith("session=")) {
                // ruleid: java-return-element-inside-loop
                return cookie.substring(8); // Returns first session cookie value
            }
        }
        return null;
    }

    public String bad_case_14(List<LogEntry> logEntries, String errorLevel) {
        for (LogEntry entry : logEntries) {
            if (entry.getLevel().equals(errorLevel)) {
                // ruleid: java-return-element-inside-loop
                return entry.getMessage(); // Returns first matching log message
            }
        }
        return null;
    }

    public String bad_case_15(String[] ipAddresses, String subnet) {
        for (String ip : ipAddresses) {
            if (ip.startsWith(subnet)) {
                // ruleid: java-return-element-inside-loop
                return ip; // Returns first IP in subnet without checking others
            }
        }
        return null;
    }

    // True Negative Examples (Safe Code)

    public List<String> good_case_1(List<User> users, String targetUsername) {
        // ok: java-return-element-inside-loop
        List<String> matchingTokens = new ArrayList<>();
        for (User user : users) {
            if (user.getUsername().equals(targetUsername)) {
                matchingTokens.add(user.getAuthToken());
            }
        }
        return matchingTokens; // Returns all matching tokens
    }

    public List<File> good_case_2(List<String> filePaths) {
        // ok: java-return-element-inside-loop
        List<File> readableFiles = new ArrayList<>();
        for (String path : filePaths) {
            File file = new File(path);
            if (file.exists() && file.canRead()) {
                readableFiles.add(file);
            }
        }
        return readableFiles; // Returns all readable files
    }

    public List<User> good_case_3(Map<Integer, User> userMap, String role) {
        // ok: java-return-element-inside-loop
        List<User> matchingUsers = new ArrayList<>();
        for (User user : userMap.values()) {
            if (user.getRole().equals(role)) {
                matchingUsers.add(user);
            }
        }
        return matchingUsers; // Returns all users with matching role
    }

    public Connection good_case_4(List<DatabaseConfig> configs) {
        // ok: java-return-element-inside-loop
        List<Connection> validConnections = new ArrayList<>();
        for (DatabaseConfig config : configs) {
            try {
                Connection conn = DriverManager.getConnection(
                    config.getUrl(), config.getUsername(), config.getPassword());
                if (conn != null && !conn.isClosed()) {
                    validConnections.add(conn);
                }
            } catch (SQLException e) {
                // Continue to next config
            }
        }
        
        // After collecting all connections, choose the appropriate one
        if (!validConnections.isEmpty()) {
            return validConnections.get(0);
        }
        return null;
    }

    public String good_case_5(HttpServletRequest request) {
        String[] allowedRoles = request.getParameterValues("role");
        String userRole = request.getParameter("userRole");
        
        // ok: java-return-element-inside-loop
        List<String> matchingRoles = new ArrayList<>();
        for (String role : allowedRoles) {
            if (role.equalsIgnoreCase(userRole)) {
                matchingRoles.add(role);
            }
        }
        
        if (matchingRoles.size() == 1) {
            return matchingRoles.get(0);
        } else if (matchingRoles.size() > 1) {
            // Handle multiple matches appropriately
            return matchingRoles.get(0); // Or some other logic
        }
        return null;
    }

    public List<Integer> good_case_6(int[] numbers, int threshold) {
        // ok: java-return-element-inside-loop
        List<Integer> matchingNumbers = new ArrayList<>();
        for (int i = 0; i < numbers.length; i++) {
            if (numbers[i] > threshold) {
                matchingNumbers.add(numbers[i]);
            }
        }
        return matchingNumbers; // Returns all numbers above threshold
    }

    public List<String> good_case_7(List<String> permissions, String userId) {
        // ok: java-return-element-inside-loop
        List<String> userPermissions = new ArrayList<>();
        for (String permission : permissions) {
            if (permission.startsWith(userId + ":")) {
                userPermissions.add(permission.substring(userId.length() + 1));
            }
        }
        return userPermissions; // Returns all permissions for the user
    }

    public List<String> good_case_8(Map<String, List<String>> resourceMap, String resourceType) {
        // ok: java-return-element-inside-loop
        List<String> matchingResources = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : resourceMap.entrySet()) {
            List<String> resources = entry.getValue();
            for (String resource : resources) {
                if (resource.contains(resourceType)) {
                    matchingResources.add(resource);
                }
            }
        }
        return matchingResources; // Returns all matching resources
    }

    public List<String> good_case_9(String[] lines, String searchTerm) {
        // ok: java-return-element-inside-loop
        List<String> matchingLines = new ArrayList<>();
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].contains(searchTerm)) {
                matchingLines.add(lines[i]);
            }
        }
        return matchingLines; // Returns all lines containing search term
    }

    public List<File> good_case_10(String directory, String fileExtension) {
        // ok: java-return-element-inside-loop
        List<File> matchingFiles = new ArrayList<>();
        File dir = new File(directory);
        File[] files = dir.listFiles();
        
        if (files != null) {
            for (File file : files) {
                if (file.getName().endsWith(fileExtension)) {
                    matchingFiles.add(file);
                }
            }
        }
        return matchingFiles; // Returns all files with matching extension
    }

    public List<String> good_case_11(ResultSet resultSet) throws SQLException {
        // ok: java-return-element-inside-loop
        List<String> activeIds = new ArrayList<>();
        while (resultSet.next()) {
            String status = resultSet.getString("status");
            if ("AC_REDACTED_TWILIO_ID".equals(status)) {
                activeIds.add(resultSet.getString("id"));
            }
        }
        return activeIds; // Returns all active record IDs
    }

    public List<Integer> good_case_12(List<Transaction> transactions, String accountId) {
        // ok: java-return-element-inside-loop
        List<Integer> largeTransactionIds = new ArrayList<>();
        for (Transaction transaction : transactions) {
            if (transaction.getAccountId().equals(accountId) && transaction.getAmount() > 1000) {
                largeTransactionIds.add(transaction.getId());
            }
        }
        return largeTransactionIds; // Returns all large transaction IDs
    }

    public List<String> good_case_13(HttpServletRequest request) {
        String[] cookies = request.getParameterValues("cookies");
        
        // ok: java-return-element-inside-loop
        List<String> sessionValues = new ArrayList<>();
        for (String cookie : cookies) {
            if (cookie.startsWith("session=")) {
                sessionValues.add(cookie.substring(8));
            }
        }
        return sessionValues; // Returns all session cookie values
    }

    public List<String> good_case_14(List<LogEntry> logEntries, String errorLevel) {
        // ok: java-return-element-inside-loop
        return logEntries.stream()
                .filter(entry -> entry.getLevel().equals(errorLevel))
                .map(LogEntry::getMessage)
                .collect(Collectors.toList()); // Using streams to collect all matching messages
    }

    public List<String> good_case_15(String[] ipAddresses, String subnet) {
        // ok: java-return-element-inside-loop
        List<String> matchingIps = new ArrayList<>();
        for (String ip : ipAddresses) {
            if (ip.startsWith(subnet)) {
                matchingIps.add(ip);
            }
        }
        return matchingIps; // Returns all IPs in subnet
    }

    // Helper classes for examples
    private static class User {
        private String username;
        private String authToken;
        private String role;

        public String getUsername() { return username; }
        public String getAuthToken() { return authToken; }
        public String getRole() { return role; }
    }

    private static class DatabaseConfig {
        private String url;
        private String username;
        private String password;

        public String getUrl() { return url; }
        public String getUsername() { return username; }
        public String getPassword() { return password; }
    }

    private static class Transaction {
        private Integer id;
        private String accountId;
        private double amount;

        public Integer getId() { return id; }
        public String getAccountId() { return accountId; }
        public double getAmount() { return amount; }
    }

    private static class LogEntry {
        private String level;
        private String message;

        public String getLevel() { return level; }
        public String getMessage() { return message; }
    }
}
// {/fact}