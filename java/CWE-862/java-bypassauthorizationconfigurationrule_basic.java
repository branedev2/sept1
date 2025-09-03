package com.example.securitytests;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// True Positive Examples (Vulnerable Code)

@RestController
public class AuthorizationBypassExamples extends HttpServlet {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    // Example 1: Missing authorization check for admin functionality
// {fact rule=missing-authorization@v1.0 defects=1}
    @GetMapping("/admin/users")
    public String bad_case_1(HttpServletRequest request) {
        // ruleid: java-bypassauthorizationconfigurationrule
        return getAllUsers(); // No authorization check before accessing admin functionality
    }
    
    // Example 2: Direct object reference without authorization check
    @GetMapping("/users/{userId}/profile")
    public String bad_case_2(@PathVariable("userId") Long userId) {
        // ruleid: java-bypassauthorizationconfigurationrule
        return getUserProfile(userId); // No check if the current user has permission to access this profile
    }
    
    // Example 3: Sensitive operation without proper authorization
    @PostMapping("/users/{userId}/delete")
    public String bad_case_3(@PathVariable("userId") Long userId) {
        // ruleid: java-bypassauthorizationconfigurationrule
        deleteUser(userId); // No authorization check before deleting a user
        return "User deleted successfully";
    }
    
    // Example 4: Authorization check bypassed with a flag parameter
    @GetMapping("/documents/{docId}")
    public String bad_case_4(@PathVariable("docId") Long docId, @RequestParam(value = "skipAuth", required = false) Boolean skipAuth) {
        if (skipAuth != null && skipAuth) {
            // ruleid: java-bypassauthorizationconfigurationrule
            return getDocument(docId); // Authorization check bypassed with a flag
        }
        
        // Some authorization check here
        return getDocument(docId);
    }
    
    // Example 5: Missing authorization in servlet
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String action = request.getParameter("action");
        if ("exportData".equals(action)) {
            // ruleid: java-bypassauthorizationconfigurationrule
            exportSensitiveData(response); // No authorization check before exporting sensitive data
        }
    }
    
    // Example 6: Authorization check in comment only
    @GetMapping("/api/financial-reports")
    public String bad_case_6() {
        // TODO: Add authorization check here
        // ruleid: java-bypassauthorizationconfigurationrule
        return getFinancialReports(); // Authorization mentioned in comment but not implemented
    }
    
    // Example 7: Bypassing authorization with a debug parameter
    @GetMapping("/api/user-settings")
    public String bad_case_7(HttpServletRequest request) {
        String debugMode = request.getParameter("debug");
        if ("true".equals(debugMode)) {
            // ruleid: java-bypassauthorizationconfigurationrule
            return getAllUserSettings(); // Debug parameter bypasses authorization
        }
        
        // Normal flow with authorization
        return "Access denied";
    }
    
    // Example 8: Missing authorization check in database operation
    @GetMapping("/api/customer/{customerId}")
    public String bad_case_8(@PathVariable("customerId") Long customerId) {
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password")) {
            // ruleid: java-bypassauthorizationconfigurationrule
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM customers WHERE id = ?");
            stmt.setLong(1, customerId);
            ResultSet rs = stmt.executeQuery(); // No authorization check before querying customer data
            // Process results
            return "Customer data";
        } catch (SQLException e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Example 9: Authorization check that's always true
    @GetMapping("/api/payment-info")
    public String bad_case_9(HttpServletRequest request) {
        boolean isAuthorized = true; // Always true
        
        if (isAuthorized) {
            // ruleid: java-bypassauthorizationconfigurationrule
            return getPaymentInfo(); // Authorization check is meaningless
        }
        
        return "Access denied";
    }
    
    // Example 10: Authorization based on user-controlled input
    @GetMapping("/api/reports")
    public String bad_case_10(HttpServletRequest request) {
        String userRole = request.getParameter("role");
        
        if ("admin".equals(userRole)) {
            // ruleid: java-bypassauthorizationconfigurationrule
            return getAdminReports(); // Authorization based on user-provided role
        }
        
        return "Access denied";
    }
    
    // Example 11: Missing authorization in file access
    @GetMapping("/download")
    public void bad_case_11(@RequestParam("file") String fileName, HttpServletResponse response) throws IOException {
        // ruleid: java-bypassauthorizationconfigurationrule
        // Direct file access without authorization check
        java.nio.file.Files.copy(
            java.nio.file.Paths.get("/sensitive/data/" + fileName),
            response.getOutputStream()
        );
    }
    
    // Example 12: Commented out authorization check
    @PostMapping("/api/system/config")
    public String bad_case_12(@RequestParam("setting") String setting, @RequestParam("value") String value) {
        /*
        if (!isAdmin()) {
            return "Access denied";
        }
        */
        
        // ruleid: java-bypassauthorizationconfigurationrule
        updateSystemConfig(setting, value); // Authorization check is commented out
        return "Configuration updated";
    }
    
    // Example 13: Authorization check in a separate method that's never called
    @PostMapping("/api/update-permissions")
    public String bad_case_13(@RequestParam("userId") Long userId, @RequestParam("permission") String permission) {
        // The authorization check method exists but is never called
        
        // ruleid: java-bypassauthorizationconfigurationrule
        updateUserPermissions(userId, permission); // Missing authorization check
        return "Permissions updated";
    }
    
    private boolean checkPermissions() {
        // This method is never called
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }
    
    // Example 14: Authorization check with hardcoded bypass
    @GetMapping("/api/logs")
    public String bad_case_14(HttpServletRequest request) {
        HttpSession session = request.getSession();
        String username = (String) session.getAttribute("username");
        
        if ("admin".equals(username) || "system".equals(username) || true) { // Always true
            // ruleid: java-bypassauthorizationconfigurationrule
            return getSystemLogs(); // Authorization check with hardcoded bypass
        }
        
        return "Access denied";
    }
    
    // Example 15: Missing authorization in API endpoint
    @RequestMapping("/api/reset-password")
    public String bad_case_15(@RequestParam("userId") Long userId, @RequestParam("newPassword") String newPassword) {
        // ruleid: java-bypassauthorizationconfigurationrule
        resetUserPassword(userId, newPassword); // No authorization check before resetting password
        return "Password reset successful";
    }
    
    // True Negative Examples (Secure Code)
    
    // Example 1: Proper authorization check using Spring Security
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users-secure")
    public String good_case_1() {
        // ok: java-bypassauthorizationconfigurationrule
        return getAllUsers(); // Protected by Spring Security @PreAuthorize
    }
    
    // Example 2: Proper authorization check for direct object reference
    @GetMapping("/users/{userId}/profile-secure")
    public String good_case_2(@PathVariable("userId") Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) auth.getPrincipal();
        
        if (userDetails.getUsername().equals(getUsernameById(userId)) || hasAdminRole(auth)) {
            // ok: java-bypassauthorizationconfigurationrule
            return getUserProfile(userId); // Access granted only to the user or admin
        }
        
        return "Access denied";
    }
    
    // Example 3: Proper authorization for sensitive operation
    @PostMapping("/users/{userId}/delete-secure")
    public String good_case_3(@PathVariable("userId") Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (hasAdminRole(auth)) {
            // ok: java-bypassauthorizationconfigurationrule
            deleteUser(userId); // Only admins can delete users
            return "User deleted successfully";
        }
        
        return "Access denied: Admin privileges required";
    }
    
    // Example 4: Proper authorization check that cannot be bypassed
    @GetMapping("/documents/{docId}/secure")
    public String good_case_4(@PathVariable("docId") Long docId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (canAccessDocument(auth, docId)) {
            // ok: java-bypassauthorizationconfigurationrule
            return getDocument(docId); // Access controlled by authorization check
        }
        
        return "Access denied";
    }
    
    // Example 5: Proper authorization in servlet
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String action = request.getParameter("action");
        
        if ("exportData".equals(action)) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            
            if (hasAdminRole(auth)) {
                // ok: java-bypassauthorizationconfigurationrule
                exportSensitiveData(response); // Only admins can export data
            } else {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            }
        }
    }
    
    // Example 6: Proper authorization check for financial reports
    @PreAuthorize("hasRole('FINANCE') or hasRole('ADMIN')")
    @GetMapping("/api/financial-reports-secure")
    public String good_case_6() {
        // ok: java-bypassauthorizationconfigurationrule
        return getFinancialReports(); // Protected by Spring Security @PreAuthorize
    }
    
    // Example 7: Debug mode with proper authorization
    @GetMapping("/api/user-settings-secure")
    public String good_case_7(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String debugMode = request.getParameter("debug");
        
        if ("true".equals(debugMode) && hasAdminRole(auth)) {
            // ok: java-bypassauthorizationconfigurationrule
            return getAllUserSettings(); // Debug mode still requires admin privileges
        } else if (hasUserRole(auth)) {
            return getCurrentUserSettings(auth);
        }
        
        return "Access denied";
    }
    
    // Example 8: Proper authorization check in database operation
    @GetMapping("/api/customer/{customerId}/secure")
    public String good_case_8(@PathVariable("customerId") Long customerId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (isCustomerOwner(auth, customerId) || hasAdminRole(auth)) {
            try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "password")) {
                // ok: java-bypassauthorizationconfigurationrule
                PreparedStatement stmt = conn.prepareStatement("SELECT * FROM customers WHERE id = ?");
                stmt.setLong(1, customerId);
                ResultSet rs = stmt.executeQuery(); // Database access after authorization check
                // Process results
                return "Customer data";
            } catch (SQLException e) {
                return "Error: " + e.getMessage();
            }
        }
        
        return "Access denied";
    }
    
    // Example 9: Proper dynamic authorization check
    @GetMapping("/api/payment-info-secure")
    public String good_case_9(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthorized = hasRole(auth, "FINANCE") || isAccountOwner(auth, request.getParameter("accountId"));
        
        if (isAuthorized) {
            // ok: java-bypassauthorizationconfigurationrule
            return getPaymentInfo(); // Authorization based on actual user roles
        }
        
        return "Access denied";
    }
    
    // Example 10: Authorization based on authenticated user's role
    @GetMapping("/api/reports-secure")
    public String good_case_10() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (hasAdminRole(auth)) {
            // ok: java-bypassauthorizationconfigurationrule
            return getAdminReports(); // Authorization based on authenticated user's role
        }
        
        return "Access denied";
    }
    
    // Example 11: Proper authorization in file access
    @GetMapping("/download-secure")
    public void good_case_11(@RequestParam("file") String fileName, HttpServletResponse response) throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (canAccessFile(auth, fileName)) {
            // ok: java-bypassauthorizationconfigurationrule
            java.nio.file.Files.copy(
                java.nio.file.Paths.get("/sensitive/data/" + fileName),
                response.getOutputStream()
            ); // File access after authorization check
        } else {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        }
    }
    
    // Example 12: Proper authorization check for system configuration
    @PostMapping("/api/system/config-secure")
    public String good_case_12(@RequestParam("setting") String setting, @RequestParam("value") String value) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (hasAdminRole(auth)) {
            // ok: java-bypassauthorizationconfigurationrule
            updateSystemConfig(setting, value); // Only admins can update system configuration
            return "Configuration updated";
        }
        
        return "Access denied: Admin privileges required";
    }
    
    // Example 13: Proper authorization check that is actually called
    @PostMapping("/api/update-permissions-secure")
    public String good_case_13(@RequestParam("userId") Long userId, @RequestParam("permission") String permission) {
        if (checkPermissionsForUpdate()) {
            // ok: java-bypassauthorizationconfigurationrule
            updateUserPermissions(userId, permission); // Authorization check is called
            return "Permissions updated";
        }
        
        return "Access denied";
    }
    
    private boolean checkPermissionsForUpdate() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }
    
    // Example 14: Proper authorization check without hardcoded bypass
    @GetMapping("/api/logs-secure")
    public String good_case_14(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (hasAdminRole(auth) || hasRole(auth, "SYSTEM_MONITOR")) {
            // ok: java-bypassauthorizationconfigurationrule
            return getSystemLogs(); // Only users with specific roles can access logs
        }
        
        return "Access denied";
    }
    
    // Example 15: Proper authorization for password reset
    @RequestMapping("/api/reset-password-secure")
    public String good_case_15(@RequestParam("userId") Long userId, @RequestParam("newPassword") String newPassword) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (isUserSelf(auth, userId) || hasAdminRole(auth)) {
            // ok: java-bypassauthorizationconfigurationrule
            resetUserPassword(userId, newPassword); // Only the user or admin can reset password
            return "Password reset successful";
        }
        
        return "Access denied";
    }
    
    // Helper methods
    private String getAllUsers() {
        return "List of all users";
    }
    
    private String getUserProfile(Long userId) {
        return "User profile for ID: " + userId;
    }
    
    private void deleteUser(Long userId) {
        // Delete user logic
    }
    
    private String getDocument(Long docId) {
        return "Document content for ID: " + docId;
    }
    
    private void exportSensitiveData(HttpServletResponse response) throws IOException {
        // Export sensitive data logic
    }
    
    private String getFinancialReports() {
        return "Financial reports data";
    }
    
    private String getAllUserSettings() {
        return "All user settings";
    }
    
    private String getCurrentUserSettings(Authentication auth) {
        return "Settings for current user";
    }
    
    private void updateSystemConfig(String setting, String value) {
        // Update system configuration logic
    }
    
    private void updateUserPermissions(Long userId, String permission) {
        // Update user permissions logic
    }
    
    private String getSystemLogs() {
        return "System logs";
    }
    
    private void resetUserPassword(Long userId, String newPassword) {
        // Reset user password logic
    }
    
    private String getAdminReports() {
        return "Admin reports";
    }
    
    private String getUsernameById(Long userId) {
        return "user" + userId;
    }
    
    private boolean hasAdminRole(Authentication auth) {
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }
    
    private boolean hasUserRole(Authentication auth) {
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_USER"));
    }
    
    private boolean hasRole(Authentication auth, String role) {
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + role));
    }
    
    private boolean canAccessDocument(Authentication auth, Long docId) {
        // Check if user can access the document
        return true; // Simplified for example
    }
    
    private boolean isCustomerOwner(Authentication auth, Long customerId) {
        // Check if user is the owner of the customer account
        return true; // Simplified for example
    }
    
    private boolean isAccountOwner(Authentication auth, String accountId) {
        // Check if user is the owner of the account
        return true; // Simplified for example
    }
    
    private boolean canAccessFile(Authentication auth, String fileName) {
        // Check if user can access the file
        return true; // Simplified for example
    }
    
    private boolean isUserSelf(Authentication auth, Long userId) {
        // Check if the authenticated user is the same as userId
        return true; // Simplified for example
    }
}
// {/fact}