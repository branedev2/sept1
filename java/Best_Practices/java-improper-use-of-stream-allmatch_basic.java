import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;
import java.util.Set;
import java.util.HashSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.function.Predicate;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class StreamAllMatchExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String userInput = request.getParameter("userIds");
        List<String> userIds = userInput != null ? 
            Arrays.asList(userInput.split(",")) : 
            Collections.emptyList();
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allValid = userIds.stream()
                .allMatch(id -> id.length() > 5);
        
        // This could be a security issue if empty input leads to bypassing validation
        if (allValid) {
            System.out.println("All user IDs are valid");
            // Proceed with sensitive operation
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        String[] roles = request.getParameterValues("roles");
        List<String> rolesList = roles != null ? 
            Arrays.asList(roles) : 
            new ArrayList<>();
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allAdminRoles = rolesList.stream()
                .allMatch(role -> role.startsWith("ADMIN_"));
        
        if (allAdminRoles) {
            System.out.println("User has all admin roles");
            // Grant admin privileges
        }
    }

    public void bad_case_3(HttpServletRequest request) {
        String inputData = request.getParameter("data");
        List<Integer> numbers = new ArrayList<>();
        if (inputData != null) {
            for (String num : inputData.split(",")) {
                try {
                    numbers.add(Integer.parseInt(num));
                } catch (NumberFormatException e) {
                    // Ignore invalid numbers
                }
            }
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allPositive = numbers.stream()
                .allMatch(num -> num > 0);
        
        if (allPositive) {
            System.out.println("All numbers are positive");
            // Perform operation requiring positive numbers
        }
    }

    public void bad_case_4(HttpServletRequest request) {
        String filePathsParam = request.getParameter("filePaths");
        List<String> filePaths = new ArrayList<>();
        if (filePathsParam != null) {
            filePaths = Arrays.asList(filePathsParam.split(";"));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allSafePaths = filePaths.stream()
                .allMatch(path -> !path.contains("../") && !path.contains("..\\"));
        
        if (allSafePaths) {
            System.out.println("All file paths are safe");
            // Access files
        }
    }

    public void bad_case_5(HttpServletRequest request) {
        String passwordsParam = request.getParameter("passwords");
        List<String> passwords = new ArrayList<>();
        if (passwordsParam != null) {
            passwords = Arrays.asList(passwordsParam.split(","));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allStrongPasswords = passwords.stream()
                .allMatch(pwd -> pwd.length() >= 8 && pwd.matches(".*[A-Z].*") && 
                           pwd.matches(".*[a-z].*") && pwd.matches(".*[0-9].*"));
        
        if (allStrongPasswords) {
            System.out.println("All passwords meet security requirements");
            // Update passwords
        }
    }

    public void bad_case_6() {
        List<String> accessTokens = getAccessTokens(); // Could return empty list
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allValid = accessTokens.stream()
                .allMatch(token -> validateToken(token));
        
        if (allValid) {
            System.out.println("All tokens are valid");
            // Grant access to protected resource
        }
    }

    private List<String> getAccessTokens() {
        // Implementation that might return empty list
        return new ArrayList<>();
    }
    
    private boolean validateToken(String token) {
        // Token validation logic
        return token != null && token.length() > 10;
    }

    public void bad_case_7(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        List<String> parameters = new ArrayList<>();
        
        if (parameterMap.containsKey("securityChecks")) {
            parameters = Arrays.asList(parameterMap.get("securityChecks"));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allParametersValid = parameters.stream()
                .allMatch(param -> param != null && !param.contains("<script>"));
        
        if (allParametersValid) {
            System.out.println("All parameters passed security checks");
            // Process parameters
        }
    }

    public void bad_case_8() {
        List<User> users = fetchUsersFromDatabase(); // Could return empty list
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allUsersVerified = users.stream()
                .allMatch(user -> user.isEmailVerified());
        
        if (allUsersVerified) {
            System.out.println("All users have verified emails");
            // Send sensitive information
        }
    }
    
    private List<User> fetchUsersFromDatabase() {
        // Database query that might return empty list
        return new ArrayList<>();
    }

    public void bad_case_9(HttpServletRequest request) {
        String ipAddresses = request.getParameter("ipAllowList");
        List<String> ipList = new ArrayList<>();
        
        if (ipAddresses != null) {
            ipList = Arrays.asList(ipAddresses.split(","));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allValidIps = ipList.stream()
                .allMatch(ip -> ip.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"));
        
        if (allValidIps) {
            System.out.println("All IP addresses are valid");
            // Update IP allowlist
        }
    }

    public void bad_case_10(HttpServletRequest request) {
        String certificatesParam = request.getParameter("certificates");
        List<String> certificates = new ArrayList<>();
        
        if (certificatesParam != null) {
            certificates = Arrays.asList(certificatesParam.split(";"));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allValidCerts = certificates.stream()
                .allMatch(cert -> cert.startsWith("-----BEGIN CERTIFICATE-----"));
        
        if (allValidCerts) {
            System.out.println("All certificates are in valid format");
            // Process certificates
        }
    }

    public void bad_case_11() {
        Stream<String> configValues = getConfigurationValues(); // Could be empty
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allConfigValid = configValues
                .allMatch(config -> !config.isEmpty() && !config.equals("default"));
        
        if (allConfigValid) {
            System.out.println("All configuration values are valid");
            // Apply configuration
        }
    }
    
    private Stream<String> getConfigurationValues() {
        // Method that might return empty stream
        return Stream.empty();
    }

    public void bad_case_12(HttpServletRequest request) {
        String urlsParam = request.getParameter("allowedUrls");
        List<String> urls = new ArrayList<>();
        
        if (urlsParam != null) {
            urls = Arrays.asList(urlsParam.split(","));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allSafeUrls = urls.stream()
                .allMatch(url -> url.startsWith("https://") && !url.contains("javascript:"));
        
        if (allSafeUrls) {
            System.out.println("All URLs are safe");
            // Add URLs to allowlist
        }
    }

    public void bad_case_13() {
        List<String> databaseQueries = getDatabaseQueries(); // Could be empty
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allQueriesSafe = databaseQueries.stream()
                .allMatch(query -> !query.toLowerCase().contains("drop table") && 
                           !query.toLowerCase().contains("truncate table"));
        
        if (allQueriesSafe) {
            System.out.println("All queries are safe");
            // Execute queries
        }
    }
    
    private List<String> getDatabaseQueries() {
        // Method that might return empty list
        return new ArrayList<>();
    }

    public void bad_case_14(HttpServletRequest request) {
        String permissionsParam = request.getParameter("permissions");
        Set<String> permissions = new HashSet<>();
        
        if (permissionsParam != null) {
            permissions = Arrays.stream(permissionsParam.split(","))
                    .collect(Collectors.toSet());
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allValidPermissions = permissions.stream()
                .allMatch(perm -> perm.startsWith("ROLE_") || perm.startsWith("PERM_"));
        
        if (allValidPermissions) {
            System.out.println("All permissions are valid");
            // Grant permissions
        }
    }

    public void bad_case_15() {
        List<LogEntry> securityLogs = getSecurityLogs(); // Could be empty
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean noSuspiciousActivity = securityLogs.stream()
                .allMatch(log -> log.getSeverity() < 5);
        
        if (noSuspiciousActivity) {
            System.out.println("No suspicious activity detected");
            // Continue normal operation
        }
    }
    
    private List<LogEntry> getSecurityLogs() {
        // Method that might return empty list
        return new ArrayList<>();
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(HttpServletRequest request) {
        String userInput = request.getParameter("userIds");
        List<String> userIds = userInput != null ? 
            Arrays.asList(userInput.split(",")) : 
            Collections.emptyList();
        
        // ok: java-improper-use-of-stream-allmatch
        boolean allValid = !userIds.isEmpty() && userIds.stream()
                .allMatch(id -> id.length() > 5);
        
        if (allValid) {
            System.out.println("All user IDs are valid");
            // Proceed with sensitive operation
        }
    }

    public void good_case_2(HttpServletRequest request) {
        String[] roles = request.getParameterValues("roles");
        List<String> rolesList = roles != null ? 
            Arrays.asList(roles) : 
            new ArrayList<>();
        
        // ok: java-improper-use-of-stream-allmatch
        boolean allAdminRoles = !rolesList.isEmpty() && rolesList.stream()
                .allMatch(role -> role.startsWith("ADMIN_"));
        
        if (allAdminRoles) {
            System.out.println("User has all admin roles");
            // Grant admin privileges
        }
    }

    public void good_case_3(HttpServletRequest request) {
        String inputData = request.getParameter("data");
        List<Integer> numbers = new ArrayList<>();
        if (inputData != null) {
            for (String num : inputData.split(",")) {
                try {
                    numbers.add(Integer.parseInt(num));
                } catch (NumberFormatException e) {
                    // Ignore invalid numbers
                }
            }
        }
        
        // ok: java-improper-use-of-stream-allmatch
        boolean hasNumbers = !numbers.isEmpty();
        boolean allPositive = hasNumbers && numbers.stream()
                .allMatch(num -> num > 0);
        
        if (allPositive) {
            System.out.println("All numbers are positive");
            // Perform operation requiring positive numbers
        }
    }

    public void good_case_4(HttpServletRequest request) {
        String filePathsParam = request.getParameter("filePaths");
        List<String> filePaths = new ArrayList<>();
        if (filePathsParam != null) {
            filePaths = Arrays.asList(filePathsParam.split(";"));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        boolean allSafePaths = filePaths.stream().findAny().isPresent() && 
                filePaths.stream().allMatch(path -> !path.contains("../") && !path.contains("..\\"));
        
        if (allSafePaths) {
            System.out.println("All file paths are safe");
            // Access files
        }
    }

    public void good_case_5(HttpServletRequest request) {
        String passwordsParam = request.getParameter("passwords");
        List<String> passwords = new ArrayList<>();
        if (passwordsParam != null) {
            passwords = Arrays.asList(passwordsParam.split(","));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        boolean hasPasswords = !passwords.isEmpty();
        boolean allStrongPasswords = hasPasswords && passwords.stream()
                .allMatch(pwd -> pwd.length() >= 8 && pwd.matches(".*[A-Z].*") && 
                           pwd.matches(".*[a-z].*") && pwd.matches(".*[0-9].*"));
        
        if (allStrongPasswords) {
            System.out.println("All passwords meet security requirements");
            // Update passwords
        }
    }

    public void good_case_6() {
        List<String> accessTokens = getAccessTokens(); // Could return empty list
        
        // ok: java-improper-use-of-stream-allmatch
        if (!accessTokens.isEmpty()) {
            boolean allValid = accessTokens.stream()
                    .allMatch(token -> validateToken(token));
            
            if (allValid) {
                System.out.println("All tokens are valid");
                // Grant access to protected resource
            }
        } else {
            System.out.println("No tokens to validate");
        }
    }

    public void good_case_7(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        List<String> parameters = new ArrayList<>();
        
        if (parameterMap.containsKey("securityChecks")) {
            parameters = Arrays.asList(parameterMap.get("securityChecks"));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        boolean hasParameters = parameters.stream().findAny().isPresent();
        boolean allParametersValid = hasParameters && parameters.stream()
                .allMatch(param -> param != null && !param.contains("<script>"));
        
        if (allParametersValid) {
            System.out.println("All parameters passed security checks");
            // Process parameters
        }
    }

    public void good_case_8() {
        List<User> users = fetchUsersFromDatabase(); // Could return empty list
        
        // ok: java-improper-use-of-stream-allmatch
        Optional<User> anyUser = users.stream().findAny();
        boolean allUsersVerified = anyUser.isPresent() && 
                users.stream().allMatch(user -> user.isEmailVerified());
        
        if (allUsersVerified) {
            System.out.println("All users have verified emails");
            // Send sensitive information
        }
    }

    public void good_case_9(HttpServletRequest request) {
        String ipAddresses = request.getParameter("ipAllowList");
        List<String> ipList = new ArrayList<>();
        
        if (ipAddresses != null) {
            ipList = Arrays.asList(ipAddresses.split(","));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        boolean hasIps = !ipList.isEmpty();
        boolean allValidIps = hasIps && ipList.stream()
                .allMatch(ip -> ip.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"));
        
        if (allValidIps) {
            System.out.println("All IP addresses are valid");
            // Update IP allowlist
        }
    }

    public void good_case_10(HttpServletRequest request) {
        String certificatesParam = request.getParameter("certificates");
        List<String> certificates = new ArrayList<>();
        
        if (certificatesParam != null) {
            certificates = Arrays.asList(certificatesParam.split(";"));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        if (!certificates.isEmpty()) {
            boolean allValidCerts = certificates.stream()
                    .allMatch(cert -> cert.startsWith("-----BEGIN CERTIFICATE-----"));
            
            if (allValidCerts) {
                System.out.println("All certificates are in valid format");
                // Process certificates
            }
        } else {
            System.out.println("No certificates to process");
        }
    }

    public void good_case_11() {
        Stream<String> configValues = getConfigurationValues(); // Could be empty
        List<String> configList = configValues.collect(Collectors.toList());
        
        // ok: java-improper-use-of-stream-allmatch
        boolean hasConfig = !configList.isEmpty();
        boolean allConfigValid = hasConfig && configList.stream()
                .allMatch(config -> !config.isEmpty() && !config.equals("default"));
        
        if (allConfigValid) {
            System.out.println("All configuration values are valid");
            // Apply configuration
        }
    }

    public void good_case_12(HttpServletRequest request) {
        String urlsParam = request.getParameter("allowedUrls");
        List<String> urls = new ArrayList<>();
        
        if (urlsParam != null) {
            urls = Arrays.asList(urlsParam.split(","));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        boolean hasUrls = urls.stream().findAny().isPresent();
        boolean allSafeUrls = hasUrls && urls.stream()
                .allMatch(url -> url.startsWith("https://") && !url.contains("javascript:"));
        
        if (allSafeUrls) {
            System.out.println("All URLs are safe");
            // Add URLs to allowlist
        }
    }

    public void good_case_13() {
        List<String> databaseQueries = getDatabaseQueries(); // Could be empty
        
        // ok: java-improper-use-of-stream-allmatch
        if (!databaseQueries.isEmpty()) {
            boolean allQueriesSafe = databaseQueries.stream()
                    .allMatch(query -> !query.toLowerCase().contains("drop table") && 
                               !query.toLowerCase().contains("truncate table"));
            
            if (allQueriesSafe) {
                System.out.println("All queries are safe");
                // Execute queries
            }
        } else {
            System.out.println("No queries to execute");
        }
    }

    public void good_case_14(HttpServletRequest request) {
        String permissionsParam = request.getParameter("permissions");
        Set<String> permissions = new HashSet<>();
        
        if (permissionsParam != null) {
            permissions = Arrays.stream(permissionsParam.split(","))
                    .collect(Collectors.toSet());
        }
        
        // ok: java-improper-use-of-stream-allmatch
        boolean hasPermissions = !permissions.isEmpty();
        boolean allValidPermissions = hasPermissions && permissions.stream()
                .allMatch(perm -> perm.startsWith("ROLE_") || perm.startsWith("PERM_"));
        
        if (allValidPermissions) {
            System.out.println("All permissions are valid");
            // Grant permissions
        }
    }

    public void good_case_15() {
        List<LogEntry> securityLogs = getSecurityLogs(); // Could be empty
        
        // ok: java-improper-use-of-stream-allmatch
        boolean hasLogs = !securityLogs.isEmpty();
        boolean noSuspiciousActivity = hasLogs && securityLogs.stream()
                .allMatch(log -> log.getSeverity() < 5);
        
        if (noSuspiciousActivity) {
            System.out.println("No suspicious activity detected");
            // Continue normal operation
        } else if (!hasLogs) {
            System.out.println("No logs to analyze");
        }
    }

    // Helper classes
    private static class User {
        private boolean emailVerified;
        
        public boolean isEmailVerified() {
            return emailVerified;
        }
    }
    
    private static class LogEntry {
        private int severity;
        
        public int getSeverity() {
            return severity;
        }
    }
}
// {/fact}