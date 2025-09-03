import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.Arrays;
import java.util.Set;
import java.util.HashSet;
import java.util.stream.Collectors;
import java.io.File;
import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.SQLException;

public class ReturnElementInsideLoopExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=resource-leak@v1.0 defects=1}
    public User bad_case_1(List<User> users, String targetUsername) {
        for (User user : users) {
            if (user.getUsername().equals(targetUsername)) {
                // ruleid: java-return-element-inside-loop
                return user; // Returns first matching user without checking if multiple users have the same username
            }
        }
        return null;
    }

    public String bad_case_2(HttpServletRequest request) {
        String userId = request.getParameter("id");
        List<String> adminIds = Arrays.asList("admin1", "admin2", "admin3");
        
        for (String id : adminIds) {
            if (id.equals(userId)) {
                // ruleid: java-return-element-inside-loop
                return "Admin access granted"; // Returns on first match without checking all possible admin IDs
            }
        }
        return "Access denied";
    }

    public File bad_case_3(String filename) {
        List<String> directories = Arrays.asList("/home/user/docs", "/var/data", "/tmp");
        
        for (String dir : directories) {
            File file = new File(dir + "/" + filename);
            if (file.exists()) {
                // ruleid: java-return-element-inside-loop
                return file; // Returns first matching file without checking other directories
            }
        }
        return null;
    }

    public Connection bad_case_4(List<String> connectionStrings, String username, String password) {
        for (String connString : connectionStrings) {
            try {
                Connection conn = DriverManager.getConnection(connString, username, password);
                if (conn != null && !conn.isClosed()) {
                    // ruleid: java-return-element-inside-loop
                    return conn; // Returns first successful connection without trying others
                }
            } catch (SQLException e) {
                // Continue to next connection string
            }
        }
        return null;
    }

    public String bad_case_5(Map<String, String> userRoles, String targetRole) {
        for (Map.Entry<String, String> entry : userRoles.entrySet()) {
            if (entry.getValue().equals(targetRole)) {
                // ruleid: java-return-element-inside-loop
                return entry.getKey(); // Returns first user with matching role without checking others
            }
        }
        return null;
    }

    public Integer bad_case_6(int[] numbers, int threshold) {
        for (int i = 0; i < numbers.length; i++) {
            if (numbers[i] > threshold) {
                // ruleid: java-return-element-inside-loop
                return numbers[i]; // Returns first number above threshold without checking others
            }
        }
        return null;
    }

    public String bad_case_7(HttpServletRequest request) {
        String searchTerm = request.getParameter("search");
        List<String> sensitiveData = Arrays.asList("SSN123", "CC456", "Password789");
        
        for (String data : sensitiveData) {
            if (data.contains(searchTerm)) {
                // ruleid: java-return-element-inside-loop
                return data; // Returns first sensitive data match without checking others
            }
        }
        return "No matches found";
    }

    public String bad_case_8(List<String> apiKeys, String service) {
        for (String key : apiKeys) {
            if (key.startsWith(service)) {
                // ruleid: java-return-element-inside-loop
                return key; // Returns first API key for service without checking for others
            }
        }
        return null;
    }

    public String bad_case_9(Map<String, Set<String>> resourcePermissions, String userId, String resource) {
        Set<String> permissions = resourcePermissions.get(resource);
        if (permissions != null) {
            for (String permission : permissions) {
                if (permission.startsWith(userId)) {
                    // ruleid: java-return-element-inside-loop
                    return permission.substring(userId.length()); // Returns first permission without checking others
                }
            }
        }
        return null;
    }

    public ResultSet bad_case_10(List<Connection> connections, String query) throws SQLException {
        for (Connection conn : connections) {
            if (!conn.isClosed()) {
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(query);
                if (rs.next()) {
                    // ruleid: java-return-element-inside-loop
                    return rs; // Returns result from first valid connection without checking others
                }
            }
        }
        return null;
    }

    public String bad_case_11(String[] paths, String filename) {
        for (String path : paths) {
            File file = new File(path + "/" + filename);
            if (file.canRead()) {
                // ruleid: java-return-element-inside-loop
                return file.getAbsolutePath(); // Returns first readable file path without checking others
            }
        }
        return null;
    }

    public User bad_case_12(HttpServletRequest request, List<User> users) {
        String role = request.getParameter("role");
        
        for (User user : users) {
            if (user.getRole().equals(role)) {
                // ruleid: java-return-element-inside-loop
                return user; // Returns first user with matching role without checking others
            }
        }
        return null;
    }

    public String bad_case_13(Map<String, List<String>> userPermissions, String username, String resource) {
        List<String> permissions = userPermissions.get(username);
        if (permissions != null) {
            for (String permission : permissions) {
                if (permission.contains(resource)) {
                    // ruleid: java-return-element-inside-loop
                    return permission; // Returns first matching permission without checking others
                }
            }
        }
        return null;
    }

    public Integer bad_case_14(int[][] matrix, int target) {
        for (int i = 0; i < matrix.length; i++) {
            for (int j = 0; j < matrix[i].length; j++) {
                if (matrix[i][j] == target) {
                    // ruleid: java-return-element-inside-loop
                    return i * matrix[i].length + j; // Returns position of first match without checking others
                }
            }
        }
        return -1;
    }

    public String bad_case_15(List<Map<String, String>> records, String key, String value) {
        for (Map<String, String> record : records) {
            if (record.containsKey(key) && record.get(key).equals(value)) {
                // ruleid: java-return-element-inside-loop
                return record.toString(); // Returns first matching record without checking others
            }
        }
        return null;
    }

    // True Negative Examples (Safe Code)

    public List<User> good_case_1(List<User> users, String targetUsername) {
        List<User> matchingUsers = new ArrayList<>();
        for (User user : users) {
            if (user.getUsername().equals(targetUsername)) {
                // ok: java-return-element-inside-loop
                matchingUsers.add(user); // Collects all matching users
            }
        }
        return matchingUsers; // Returns all matches after loop completes
    }

    public String good_case_2(HttpServletRequest request) {
        String userId = request.getParameter("id");
        List<String> adminIds = Arrays.asList("admin1", "admin2", "admin3");
        
        boolean isAdmin = false;
        for (String id : adminIds) {
            if (id.equals(userId)) {
                // ok: java-return-element-inside-loop
                isAdmin = true; // Marks as admin but continues checking
                break;
            }
        }
        return isAdmin ? "Admin access granted" : "Access denied"; // Returns after loop completes
    }

    public List<File> good_case_3(String filename) {
        List<String> directories = Arrays.asList("/home/user/docs", "/var/data", "/tmp");
        List<File> matchingFiles = new ArrayList<>();
        
        for (String dir : directories) {
            File file = new File(dir + "/" + filename);
            if (file.exists()) {
                // ok: java-return-element-inside-loop
                matchingFiles.add(file); // Collects all matching files
            }
        }
        return matchingFiles; // Returns all matches after loop completes
    }

    public Connection good_case_4(List<String> connectionStrings, String username, String password) {
        List<Connection> validConnections = new ArrayList<>();
        for (String connString : connectionStrings) {
            try {
                Connection conn = DriverManager.getConnection(connString, username, password);
                if (conn != null && !conn.isClosed()) {
                    // ok: java-return-element-inside-loop
                    validConnections.add(conn); // Collects all valid connections
                }
            } catch (SQLException e) {
                // Continue to next connection string
            }
        }
        
        // Return first valid connection or null after checking all
        return validConnections.isEmpty() ? null : validConnections.get(0);
    }

    public List<String> good_case_5(Map<String, String> userRoles, String targetRole) {
        List<String> usersWithRole = new ArrayList<>();
        for (Map.Entry<String, String> entry : userRoles.entrySet()) {
            if (entry.getValue().equals(targetRole)) {
                // ok: java-return-element-inside-loop
                usersWithRole.add(entry.getKey()); // Collects all users with matching role
            }
        }
        return usersWithRole; // Returns all matches after loop completes
    }

    public List<Integer> good_case_6(int[] numbers, int threshold) {
        List<Integer> matchingNumbers = new ArrayList<>();
        for (int i = 0; i < numbers.length; i++) {
            if (numbers[i] > threshold) {
                // ok: java-return-element-inside-loop
                matchingNumbers.add(numbers[i]); // Collects all numbers above threshold
            }
        }
        return matchingNumbers; // Returns all matches after loop completes
    }

    public List<String> good_case_7(HttpServletRequest request) {
        String searchTerm = request.getParameter("search");
        List<String> sensitiveData = Arrays.asList("SSN123", "CC456", "Password789");
        List<String> matches = new ArrayList<>();
        
        for (String data : sensitiveData) {
            if (data.contains(searchTerm)) {
                // ok: java-return-element-inside-loop
                matches.add(data); // Collects all matching sensitive data
            }
        }
        
        return matches.isEmpty() ? Arrays.asList("No matches found") : matches; // Returns all matches after loop completes
    }

    public List<String> good_case_8(List<String> apiKeys, String service) {
        List<String> matchingKeys = new ArrayList<>();
        for (String key : apiKeys) {
            if (key.startsWith(service)) {
                // ok: java-return-element-inside-loop
                matchingKeys.add(key); // Collects all API keys for service
            }
        }
        return matchingKeys; // Returns all matches after loop completes
    }

    public Set<String> good_case_9(Map<String, Set<String>> resourcePermissions, String userId, String resource) {
        Set<String> userPermissions = new HashSet<>();
        Set<String> permissions = resourcePermissions.get(resource);
        
        if (permissions != null) {
            for (String permission : permissions) {
                if (permission.startsWith(userId)) {
                    // ok: java-return-element-inside-loop
                    userPermissions.add(permission.substring(userId.length())); // Collects all permissions
                }
            }
        }
        return userPermissions; // Returns all matches after loop completes
    }

    public List<ResultSet> good_case_10(List<Connection> connections, String query) throws SQLException {
        List<ResultSet> results = new ArrayList<>();
        for (Connection conn : connections) {
            if (!conn.isClosed()) {
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(query);
                if (rs.next()) {
                    // ok: java-return-element-inside-loop
                    results.add(rs); // Collects all result sets
                }
            }
        }
        return results; // Returns all results after loop completes
    }

    public List<String> good_case_11(String[] paths, String filename) {
        List<String> readablePaths = new ArrayList<>();
        for (String path : paths) {
            File file = new File(path + "/" + filename);
            if (file.canRead()) {
                // ok: java-return-element-inside-loop
                readablePaths.add(file.getAbsolutePath()); // Collects all readable file paths
            }
        }
        return readablePaths; // Returns all matches after loop completes
    }

    public List<User> good_case_12(HttpServletRequest request, List<User> users) {
        String role = request.getParameter("role");
        
        // Using Java streams as an alternative approach
        // ok: java-return-element-inside-loop
        return users.stream()
                .filter(user -> user.getRole().equals(role))
                .collect(Collectors.toList()); // Returns all matches using stream
    }

    public List<String> good_case_13(Map<String, List<String>> userPermissions, String username, String resource) {
        List<String> matchingPermissions = new ArrayList<>();
        List<String> permissions = userPermissions.get(username);
        
        if (permissions != null) {
            for (String permission : permissions) {
                if (permission.contains(resource)) {
                    // ok: java-return-element-inside-loop
                    matchingPermissions.add(permission); // Collects all matching permissions
                }
            }
        }
        return matchingPermissions; // Returns all matches after loop completes
    }

    public List<Integer> good_case_14(int[][] matrix, int target) {
        List<Integer> positions = new ArrayList<>();
        for (int i = 0; i < matrix.length; i++) {
            for (int j = 0; j < matrix[i].length; j++) {
                if (matrix[i][j] == target) {
                    // ok: java-return-element-inside-loop
                    positions.add(i * matrix[i].length + j); // Collects all matching positions
                }
            }
        }
        return positions.isEmpty() ? Arrays.asList(-1) : positions; // Returns all matches after loop completes
    }

    public List<Map<String, String>> good_case_15(List<Map<String, String>> records, String key, String value) {
        List<Map<String, String>> matchingRecords = new ArrayList<>();
        for (Map<String, String> record : records) {
            if (record.containsKey(key) && record.get(key).equals(value)) {
                // ok: java-return-element-inside-loop
                matchingRecords.add(record); // Collects all matching records
            }
        }
        return matchingRecords; // Returns all matches after loop completes
    }

    // Helper class
    private static class User {
        private String username;
        private String role;
        
        public User(String username, String role) {
            this.username = username;
            this.role = role;
        }
        
        public String getUsername() {
            return username;
        }
        
        public String getRole() {
            return role;
        }
    }
}
// {/fact}