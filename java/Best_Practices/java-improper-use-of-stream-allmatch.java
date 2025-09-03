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
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class ImproperStreamAllMatchExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String userInput = request.getParameter("userIds");
        List<Integer> userIds = new ArrayList<>();
        
        if (userInput != null && !userInput.isEmpty()) {
            String[] ids = userInput.split(",");
            for (String id : ids) {
                try {
                    userIds.add(Integer.parseInt(id.trim()));
                } catch (NumberFormatException e) {
                    // Skip invalid numbers
                }
            }
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allUsersHaveAccess = userIds.stream().allMatch(id -> hasAccess(id));
        
        if (allUsersHaveAccess) {
            // Grant access - potentially dangerous if userIds is empty!
            grantGroupAccess();
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        String[] roles = request.getParameterValues("roles");
        List<String> rolesList = roles != null ? Arrays.asList(roles) : Collections.emptyList();
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allRolesValid = rolesList.stream().allMatch(role -> isValidRole(role));
        
        if (allRolesValid) {
            // This will be true even if rolesList is empty!
            assignAllRoles(request.getParameter("username"));
        }
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileData = request.getParameter("fileData");
        List<String> lines = fileData != null ? 
            Arrays.asList(fileData.split("\n")) : 
            Collections.emptyList();
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allLinesValid = lines.stream().allMatch(line -> !line.contains("../"));
        
        if (allLinesValid) {
            // This will be true even if lines is empty!
            writeToFile(lines);
            response.getWriter().println("File processed successfully");
        }
    }

    public void bad_case_4(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        List<String> passwords = new ArrayList<>();
        
        if (parameterMap.containsKey("passwords")) {
            passwords = Arrays.asList(parameterMap.get("passwords"));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allPasswordsStrong = passwords.stream().allMatch(this::isStrongPassword);
        
        if (allPasswordsStrong) {
            // This will be true even if passwords is empty!
            allowPasswordReset();
        }
    }

    public void bad_case_5() {
        List<String> configValues = getConfigValues();
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allConfigsSecure = configValues.stream().allMatch(config -> !config.contains("insecure"));
        
        if (allConfigsSecure) {
            // This will be true even if configValues is empty!
            enableSecureMode();
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        String ipAddresses = request.getParameter("allowedIps");
        List<String> ipList = new ArrayList<>();
        
        if (ipAddresses != null) {
            ipList = Arrays.asList(ipAddresses.split(","));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allIpsValid = ipList.stream().allMatch(ip -> isValidIpAddress(ip));
        
        if (allIpsValid) {
            // This will be true even if ipList is empty!
            configureFirewall(ipList);
        }
    }

    public void bad_case_7(HttpServletRequest request) {
        String userInput = request.getParameter("ports");
        List<Integer> ports = new ArrayList<>();
        
        if (userInput != null) {
            try {
                for (String port : userInput.split(",")) {
                    ports.add(Integer.parseInt(port.trim()));
                }
            } catch (NumberFormatException e) {
                // Handle exception
            }
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allPortsAllowed = ports.stream().allMatch(port -> isAllowedPort(port));
        
        if (allPortsAllowed) {
            // This will be true even if ports is empty!
            openPorts(ports);
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        String[] permissions = request.getParameterValues("permissions");
        Set<String> permissionSet = new HashSet<>();
        
        if (permissions != null) {
            permissionSet.addAll(Arrays.asList(permissions));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allPermissionsValid = permissionSet.stream().allMatch(perm -> isValidPermission(perm));
        
        if (allPermissionsValid) {
            // This will be true even if permissionSet is empty!
            grantPermissions(request.getParameter("userId"), permissionSet);
        }
    }

    public void bad_case_9(HttpServletRequest request) {
        String input = request.getParameter("securityTokens");
        List<String> tokens = new ArrayList<>();
        
        if (input != null) {
            tokens = Arrays.asList(input.split(","));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allTokensValid = tokens.stream().allMatch(token -> validateToken(token));
        
        if (allTokensValid) {
            // This will be true even if tokens is empty!
            authenticateUser(request.getParameter("username"));
        }
    }

    public void bad_case_10(HttpServletRequest request) {
        List<String> urls = new ArrayList<>();
        String urlParam = request.getParameter("urls");
        
        if (urlParam != null) {
            urls = Arrays.asList(urlParam.split(","));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allUrlsSafe = urls.stream().allMatch(url -> !url.contains("javascript:"));
        
        if (allUrlsSafe) {
            // This will be true even if urls is empty!
            allowRedirect(urls.get(0));
        }
    }

    public void bad_case_11(Connection conn, HttpServletRequest request) throws SQLException {
        String userIds = request.getParameter("userIds");
        List<Integer> idList = new ArrayList<>();
        
        if (userIds != null) {
            for (String id : userIds.split(",")) {
                try {
                    idList.add(Integer.parseInt(id.trim()));
                } catch (NumberFormatException e) {
                    // Skip invalid IDs
                }
            }
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allIdsExist = idList.stream().allMatch(id -> userExists(id, conn));
        
        if (allIdsExist) {
            // This will be true even if idList is empty!
            deleteUsers(idList, conn);
        }
    }

    public void bad_case_12() {
        Stream<String> dynamicStream = getDynamicStream();
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allElementsValid = dynamicStream.allMatch(element -> isValidElement(element));
        
        if (allElementsValid) {
            // This will be true even if dynamicStream is empty!
            processElements();
        }
    }

    public void bad_case_13(HttpServletRequest request) {
        String[] headers = request.getParameterValues("headers");
        List<String> headerList = headers != null ? Arrays.asList(headers) : Collections.emptyList();
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allHeadersSafe = headerList.stream().allMatch(header -> !header.contains("<script>"));
        
        if (allHeadersSafe) {
            // This will be true even if headerList is empty!
            setResponseHeaders(headerList);
        }
    }

    public void bad_case_14(HttpServletRequest request) {
        String certificateIds = request.getParameter("certIds");
        List<String> certList = new ArrayList<>();
        
        if (certificateIds != null) {
            certList = Arrays.asList(certificateIds.split(","));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allCertsValid = certList.stream().allMatch(cert -> validateCertificate(cert));
        
        if (allCertsValid) {
            // This will be true even if certList is empty!
            trustCertificates(certList);
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        String commandInput = request.getParameter("commands");
        List<String> commands = new ArrayList<>();
        
        if (commandInput != null) {
            commands = Arrays.asList(commandInput.split(";"));
        }
        
        // ruleid: java-improper-use-of-stream-allmatch
        boolean allCommandsSafe = commands.stream().allMatch(cmd -> !cmd.contains("rm -rf"));
        
        if (allCommandsSafe) {
            // This will be true even if commands is empty!
            executeCommands(commands);
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(HttpServletRequest request) {
        String userInput = request.getParameter("userIds");
        List<Integer> userIds = new ArrayList<>();
        
        if (userInput != null && !userInput.isEmpty()) {
            String[] ids = userInput.split(",");
            for (String id : ids) {
                try {
                    userIds.add(Integer.parseInt(id.trim()));
                } catch (NumberFormatException e) {
                    // Skip invalid numbers
                }
            }
        }
        
        // ok: java-improper-use-of-stream-allmatch
        if (!userIds.isEmpty() && userIds.stream().allMatch(id -> hasAccess(id))) {
            // Grant access - safe because we check if userIds is not empty
            grantGroupAccess();
        }
    }

    public void good_case_2(HttpServletRequest request) {
        String[] roles = request.getParameterValues("roles");
        List<String> rolesList = roles != null ? Arrays.asList(roles) : Collections.emptyList();
        
        // ok: java-improper-use-of-stream-allmatch
        if (!rolesList.isEmpty() && rolesList.stream().allMatch(role -> isValidRole(role))) {
            // Safe because we check if rolesList is not empty
            assignAllRoles(request.getParameter("username"));
        }
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileData = request.getParameter("fileData");
        List<String> lines = fileData != null ? 
            Arrays.asList(fileData.split("\n")) : 
            Collections.emptyList();
        
        // ok: java-improper-use-of-stream-allmatch
        if (!lines.isEmpty() && lines.stream().allMatch(line -> !line.contains("../"))) {
            // Safe because we check if lines is not empty
            writeToFile(lines);
            response.getWriter().println("File processed successfully");
        }
    }

    public void good_case_4(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        List<String> passwords = new ArrayList<>();
        
        if (parameterMap.containsKey("passwords")) {
            passwords = Arrays.asList(parameterMap.get("passwords"));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        boolean hasPasswords = !passwords.isEmpty();
        boolean allPasswordsStrong = passwords.stream().allMatch(this::isStrongPassword);
        
        if (hasPasswords && allPasswordsStrong) {
            // Safe because we check if passwords is not empty
            allowPasswordReset();
        }
    }

    public void good_case_5() {
        List<String> configValues = getConfigValues();
        
        // ok: java-improper-use-of-stream-allmatch
        if (configValues.stream().findAny().isPresent() && 
            configValues.stream().allMatch(config -> !config.contains("insecure"))) {
            // Safe because we check if configValues has any elements
            enableSecureMode();
        }
    }

    public void good_case_6(HttpServletRequest request) {
        String ipAddresses = request.getParameter("allowedIps");
        List<String> ipList = new ArrayList<>();
        
        if (ipAddresses != null) {
            ipList = Arrays.asList(ipAddresses.split(","));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        if (!ipList.isEmpty()) {
            boolean allIpsValid = ipList.stream().allMatch(ip -> isValidIpAddress(ip));
            if (allIpsValid) {
                // Safe because we check if ipList is not empty
                configureFirewall(ipList);
            }
        }
    }

    public void good_case_7(HttpServletRequest request) {
        String userInput = request.getParameter("ports");
        List<Integer> ports = new ArrayList<>();
        
        if (userInput != null) {
            try {
                for (String port : userInput.split(",")) {
                    ports.add(Integer.parseInt(port.trim()));
                }
            } catch (NumberFormatException e) {
                // Handle exception
            }
        }
        
        // ok: java-improper-use-of-stream-allmatch
        if (!ports.isEmpty()) {
            boolean allPortsAllowed = ports.stream().allMatch(port -> isAllowedPort(port));
            if (allPortsAllowed) {
                // Safe because we check if ports is not empty
                openPorts(ports);
            }
        }
    }

    public void good_case_8(HttpServletRequest request) {
        String[] permissions = request.getParameterValues("permissions");
        Set<String> permissionSet = new HashSet<>();
        
        if (permissions != null) {
            permissionSet.addAll(Arrays.asList(permissions));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        if (permissionSet.stream().findAny().isPresent() && 
            permissionSet.stream().allMatch(perm -> isValidPermission(perm))) {
            // Safe because we check if permissionSet has any elements
            grantPermissions(request.getParameter("userId"), permissionSet);
        }
    }

    public void good_case_9(HttpServletRequest request) {
        String input = request.getParameter("securityTokens");
        List<String> tokens = new ArrayList<>();
        
        if (input != null) {
            tokens = Arrays.asList(input.split(","));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        boolean hasTokens = tokens.stream().findFirst().isPresent();
        boolean allTokensValid = tokens.stream().allMatch(token -> validateToken(token));
        
        if (hasTokens && allTokensValid) {
            // Safe because we check if tokens has any elements
            authenticateUser(request.getParameter("username"));
        }
    }

    public void good_case_10(HttpServletRequest request) {
        List<String> urls = new ArrayList<>();
        String urlParam = request.getParameter("urls");
        
        if (urlParam != null) {
            urls = Arrays.asList(urlParam.split(","));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        if (!urls.isEmpty()) {
            boolean allUrlsSafe = urls.stream().allMatch(url -> !url.contains("javascript:"));
            if (allUrlsSafe && !urls.isEmpty()) {
                // Safe because we check if urls is not empty
                allowRedirect(urls.get(0));
            }
        }
    }

    public void good_case_11(Connection conn, HttpServletRequest request) throws SQLException {
        String userIds = request.getParameter("userIds");
        List<Integer> idList = new ArrayList<>();
        
        if (userIds != null) {
            for (String id : userIds.split(",")) {
                try {
                    idList.add(Integer.parseInt(id.trim()));
                } catch (NumberFormatException e) {
                    // Skip invalid IDs
                }
            }
        }
        
        // ok: java-improper-use-of-stream-allmatch
        if (!idList.isEmpty() && idList.stream().allMatch(id -> userExists(id, conn))) {
            // Safe because we check if idList is not empty
            deleteUsers(idList, conn);
        }
    }

    public void good_case_12() {
        Stream<String> dynamicStream = getDynamicStream();
        
        // ok: java-improper-use-of-stream-allmatch
        Optional<String> anyElement = dynamicStream.findAny();
        if (anyElement.isPresent() && getDynamicStream().allMatch(element -> isValidElement(element))) {
            // Safe because we check if dynamicStream has any elements
            processElements();
        }
    }

    public void good_case_13(HttpServletRequest request) {
        String[] headers = request.getParameterValues("headers");
        List<String> headerList = headers != null ? Arrays.asList(headers) : Collections.emptyList();
        
        // ok: java-improper-use-of-stream-allmatch
        boolean hasHeaders = !headerList.isEmpty();
        if (hasHeaders && headerList.stream().allMatch(header -> !header.contains("<script>"))) {
            // Safe because we check if headerList is not empty
            setResponseHeaders(headerList);
        }
    }

    public void good_case_14(HttpServletRequest request) {
        String certificateIds = request.getParameter("certIds");
        List<String> certList = new ArrayList<>();
        
        if (certificateIds != null) {
            certList = Arrays.asList(certificateIds.split(","));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        if (!certList.stream().noneMatch(x -> true) && 
            certList.stream().allMatch(cert -> validateCertificate(cert))) {
            // Safe because we check if certList is not empty using noneMatch
            trustCertificates(certList);
        }
    }

    public void good_case_15(HttpServletRequest request) {
        String commandInput = request.getParameter("commands");
        List<String> commands = new ArrayList<>();
        
        if (commandInput != null) {
            commands = Arrays.asList(commandInput.split(";"));
        }
        
        // ok: java-improper-use-of-stream-allmatch
        if (commands.size() > 0 && commands.stream().allMatch(cmd -> !cmd.contains("rm -rf"))) {
            // Safe because we check if commands has elements
            executeCommands(commands);
        }
    }

    // Helper methods to make the examples compile
    private boolean hasAccess(int id) { return true; }
    private void grantGroupAccess() {}
    private boolean isValidRole(String role) { return true; }
    private void assignAllRoles(String username) {}
    private void writeToFile(List<String> lines) {}
    private boolean isStrongPassword(String password) { return true; }
    private void allowPasswordReset() {}
    private List<String> getConfigValues() { return new ArrayList<>(); }
    private void enableSecureMode() {}
    private boolean isValidIpAddress(String ip) { return true; }
    private void configureFirewall(List<String> ipList) {}
    private boolean isAllowedPort(int port) { return true; }
    private void openPorts(List<Integer> ports) {}
    private boolean isValidPermission(String perm) { return true; }
    private void grantPermissions(String userId, Set<String> permissions) {}
    private boolean validateToken(String token) { return true; }
    private void authenticateUser(String username) {}
    private void allowRedirect(String url) {}
    private boolean userExists(int id, Connection conn) { return true; }
    private void deleteUsers(List<Integer> idList, Connection conn) {}
    private Stream<String> getDynamicStream() { return Stream.empty(); }
    private boolean isValidElement(String element) { return true; }
    private void processElements() {}
    private void setResponseHeaders(List<String> headers) {}
    private boolean validateCertificate(String cert) { return true; }
    private void trustCertificates(List<String> certList) {}
    private void executeCommands(List<String> commands) {}
}
// {/fact}