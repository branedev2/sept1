import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;

public class PaginationVulnerabilityExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
        int page = Integer.parseInt(request.getParameter("page"));
        int size = Integer.parseInt(request.getParameter("size"));
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            
            // ruleid: java-paginatedlistperformancerule
            ResultSet rs = stmt.executeQuery("SELECT * FROM users LIMIT " + size + " OFFSET " + (page * size));
            
            // Process only the first page of results
            List<String> users = new ArrayList<>();
            while (rs.next()) {
                users.add(rs.getString("username"));
            }
            
            // Making decisions based on incomplete data
            if (users.size() < 10) {
                // This decision is flawed as it only considers the current page
                response.getWriter().write("Few users in system, enabling debug mode");
            }
            
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2(UserRepository userRepository) {
        // Fixed page size without checking total elements
        Pageable pageable = PageRequest.of(0, 100);
        
        // ruleid: java-paginatedlistperformancerule
        Page<User> firstPage = userRepository.findAll(pageable);
        List<User> users = firstPage.getContent();
        
        // Security decision based on incomplete data
        if (users.isEmpty()) {
            System.out.println("No users found, disabling authentication checks");
        }
    }

    public void bad_case_3(AmazonDynamoDB dynamoDB) {
        ScanRequest scanRequest = new ScanRequest()
            .withTableName("UserPermissions")
            .withLimit(1000);
        
        // ruleid: java-paginatedlistperformancerule
        ScanResult result = dynamoDB.scan(scanRequest);
        
        // Not handling pagination, only processing first page
        boolean hasAdminUser = result.getItems().stream()
            .anyMatch(item -> "ADMIN".equals(item.get("role").getS()));
        
        if (!hasAdminUser) {
            System.out.println("No admin users found, creating default admin");
            // This is dangerous as there might be admin users in subsequent pages
        }
    }

    public void bad_case_4(HttpServletRequest request, JpaRepository<LogEntry, Long> logRepository) {
        String securityEvent = request.getParameter("event");
        
        // ruleid: java-paginatedlistperformancerule
        List<LogEntry> recentLogs = logRepository.findByEventType(securityEvent, PageRequest.of(0, 50)).getContent();
        
        // Making security decision based on incomplete logs
        if (recentLogs.size() < 5) {
            System.out.println("Few security events detected, reducing monitoring frequency");
        }
    }

    public void bad_case_5(Connection connection) throws SQLException {
        Statement stmt = connection.createStatement();
        
        // ruleid: java-paginatedlistperformancerule
        ResultSet rs = stmt.executeQuery("SELECT ip_address FROM failed_logins LIMIT 100");
        
        List<String> suspiciousIPs = new ArrayList<>();
        while (rs.next()) {
            suspiciousIPs.add(rs.getString("ip_address"));
        }
        
        // Incomplete blocklist due to pagination limitation
        System.out.println("Blocking IPs: " + String.join(", ", suspiciousIPs));
    }

    @RestController
    public class bad_case_6 {
        private final UserRepository userRepository;
        
        public bad_case_6(UserRepository userRepository) {
            this.userRepository = userRepository;
        }
        
        @GetMapping("/api/user-analysis")
        public String analyzeUsers(@RequestParam(defaultValue = "0") int page) {
            // ruleid: java-paginatedlistperformancerule
            Page<User> userPage = userRepository.findAll(PageRequest.of(page, 20));
            
            // Analysis on single page only
            double avgAge = userPage.getContent().stream()
                .mapToInt(User::getAge)
                .average()
                .orElse(0);
                
            return "Average user age: " + avgAge;
        }
    }

    public void bad_case_7(AmazonDynamoDB dynamoDB) {
        ScanRequest scanRequest = new ScanRequest()
            .withTableName("Transactions")
            .withLimit(500);
            
        // ruleid: java-paginatedlistperformancerule
        ScanResult result = dynamoDB.scan(scanRequest);
        
        // Calculating total without considering all pages
        double totalAmount = result.getItems().stream()
            .mapToDouble(item -> Double.parseDouble(item.get("amount").getN()))
            .sum();
            
        if (totalAmount < 10000) {
            System.out.println("Low transaction volume detected, disabling fraud checks");
        }
    }

    public void bad_case_8(HttpServletRequest request, Connection connection) throws SQLException {
        int pageSize = Integer.parseInt(request.getParameter("pageSize"));
        Statement stmt = connection.createStatement();
        
        // ruleid: java-paginatedlistperformancerule
        ResultSet rs = stmt.executeQuery("SELECT username, last_login FROM users ORDER BY last_login DESC LIMIT " + pageSize);
        
        List<String> recentlyActiveUsers = new ArrayList<>();
        while (rs.next()) {
            recentlyActiveUsers.add(rs.getString("username"));
        }
        
        // Incomplete activity analysis
        System.out.println("Active users: " + String.join(", ", recentlyActiveUsers));
    }

    public void bad_case_9(ProductRepository productRepository) {
        // ruleid: java-paginatedlistperformancerule
        List<Product> products = productRepository.findByCategory("security", PageRequest.of(0, 50)).getContent();
        
        // Incomplete inventory check
        boolean hasFirewallProducts = products.stream()
            .anyMatch(p -> p.getName().toLowerCase().contains("firewall"));
            
        if (!hasFirewallProducts) {
            System.out.println("No firewall products found, marking as security gap");
        }
    }

    public void bad_case_10(Connection connection) throws SQLException {
        Statement stmt = connection.createStatement();
        
        // ruleid: java-paginatedlistperformancerule
        ResultSet rs = stmt.executeQuery("SELECT user_id FROM permissions WHERE permission='admin' LIMIT 100");
        
        List<Integer> adminIds = new ArrayList<>();
        while (rs.next()) {
            adminIds.add(rs.getInt("user_id"));
        }
        
        // Incomplete admin check
        if (adminIds.isEmpty()) {
            System.out.println("No admins found, system may be misconfigured");
        }
    }

    public void bad_case_11(HttpServletRequest request, AuditLogRepository auditRepository) {
        String userId = request.getParameter("userId");
        
        // ruleid: java-paginatedlistperformancerule
        List<AuditLog> userLogs = auditRepository.findByUserId(userId, PageRequest.of(0, 20)).getContent();
        
        // Incomplete audit analysis
        boolean hasSuspiciousActivity = userLogs.stream()
            .anyMatch(log -> log.getAction().equals("PASSWORD_RESET") || log.getAction().equals("PERMISSION_CHANGE"));
            
        if (!hasSuspiciousActivity) {
            System.out.println("User appears safe based on limited logs");
        }
    }

    public void bad_case_12(Connection connection) throws SQLException {
        Statement stmt = connection.createStatement();
        
        // ruleid: java-paginatedlistperformancerule
        ResultSet rs = stmt.executeQuery("SELECT ip_address, COUNT(*) as count FROM access_logs GROUP BY ip_address ORDER BY count DESC LIMIT 10");
        
        List<String> topAccessors = new ArrayList<>();
        while (rs.next()) {
            topAccessors.add(rs.getString("ip_address"));
        }
        
        // Incomplete traffic analysis
        System.out.println("Top traffic sources: " + String.join(", ", topAccessors));
    }

    public void bad_case_13(ComplianceRepository complianceRepo) {
        // ruleid: java-paginatedlistperformancerule
        List<ComplianceCheck> failedChecks = complianceRepo.findByStatus("FAILED", PageRequest.of(0, 50)).getContent();
        
        // Incomplete compliance reporting
        if (failedChecks.isEmpty()) {
            System.out.println("All compliance checks passing, system is compliant");
        }
    }

    public void bad_case_14(HttpServletRequest request, VulnerabilityRepository vulnRepo) {
        String severity = request.getParameter("severity");
        
        // ruleid: java-paginatedlistperformancerule
        List<Vulnerability> criticalVulns = vulnRepo.findBySeverity(severity, PageRequest.of(0, 25)).getContent();
        
        // Incomplete vulnerability assessment
        if (criticalVulns.isEmpty()) {
            System.out.println("No critical vulnerabilities found, system is secure");
        }
    }

    public void bad_case_15(Connection connection) throws SQLException {
        Statement stmt = connection.createStatement();
        
        // ruleid: java-paginatedlistperformancerule
        ResultSet rs = stmt.executeQuery("SELECT device_id FROM devices WHERE last_updated < DATE_SUB(NOW(), INTERVAL 30 DAY) LIMIT 100");
        
        List<String> outdatedDevices = new ArrayList<>();
        while (rs.next()) {
            outdatedDevices.add(rs.getString("device_id"));
        }
        
        // Incomplete device management
        System.out.println("Outdated devices requiring updates: " + outdatedDevices.size());
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
        int page = Integer.parseInt(request.getParameter("page"));
        int size = Integer.parseInt(request.getParameter("size"));
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
            Statement stmt = conn.createStatement();
            
            // First, get total count
            ResultSet countRs = stmt.executeQuery("SELECT COUNT(*) as total FROM users");
            countRs.next();
            int totalUsers = countRs.getInt("total");
            
            // Then get paginated data
            ResultSet rs = stmt.executeQuery("SELECT * FROM users LIMIT " + size + " OFFSET " + (page * size));
            
            List<String> pageUsers = new ArrayList<>();
            while (rs.next()) {
                pageUsers.add(rs.getString("username"));
            }
            
            // ok: java-paginatedlistperformancerule
            // Making decisions based on complete data
            if (totalUsers < 10) {
                response.getWriter().write("Few users in system, enabling debug mode");
            }
            
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2(UserRepository userRepository) {
        // Get total count first
        long totalUsers = userRepository.count();
        
        // Then get paginated data if needed
        List<User> allUsers = new ArrayList<>();
        int pageSize = 100;
        int totalPages = (int) Math.ceil((double) totalUsers / pageSize);
        
        for (int i = 0; i < totalPages; i++) {
            Pageable pageable = PageRequest.of(i, pageSize);
            Page<User> userPage = userRepository.findAll(pageable);
            allUsers.addAll(userPage.getContent());
        }
        
        // ok: java-paginatedlistperformancerule
        // Security decision based on complete data
        if (allUsers.isEmpty()) {
            System.out.println("No users found, disabling authentication checks");
        }
    }

    public void good_case_3(AmazonDynamoDB dynamoDB) {
        ScanRequest scanRequest = new ScanRequest().withTableName("UserPermissions");
        List<java.util.Map<String, com.amazonaws.services.dynamodbv2.model.AttributeValue>> allItems = new ArrayList<>();
        
        ScanResult result;
        do {
            result = dynamoDB.scan(scanRequest);
            allItems.addAll(result.getItems());
            scanRequest.setExclusiveStartKey(result.getLastEvaluatedKey());
        } while (result.getLastEvaluatedKey() != null);
        
        // ok: java-paginatedlistperformancerule
        // Processing complete dataset
        boolean hasAdminUser = allItems.stream()
            .anyMatch(item -> "ADMIN".equals(item.get("role").getS()));
        
        if (!hasAdminUser) {
            System.out.println("No admin users found, creating default admin");
        }
    }

    public void good_case_4(HttpServletRequest request, JpaRepository<LogEntry, Long> logRepository) {
        String securityEvent = request.getParameter("event");
        
        // Get total count first
        long totalLogs = logRepository.countByEventType(securityEvent);
        
        List<LogEntry> allLogs = new ArrayList<>();
        int pageSize = 50;
        int totalPages = (int) Math.ceil((double) totalLogs / pageSize);
        
        for (int i = 0; i < totalPages; i++) {
            List<LogEntry> pageLogs = logRepository.findByEventType(securityEvent, PageRequest.of(i, pageSize)).getContent();
            allLogs.addAll(pageLogs);
        }
        
        // ok: java-paginatedlistperformancerule
        // Making security decision based on complete logs
        if (allLogs.size() < 5) {
            System.out.println("Few security events detected, reducing monitoring frequency");
        }
    }

    public void good_case_5(Connection connection) throws SQLException {
        Statement stmt = connection.createStatement();
        
        // First get total count
        ResultSet countRs = stmt.executeQuery("SELECT COUNT(*) as total FROM failed_logins");
        countRs.next();
        int totalFailedLogins = countRs.getInt("total");
        
        List<String> allSuspiciousIPs = new ArrayList<>();
        int pageSize = 100;
        int totalPages = (int) Math.ceil((double) totalFailedLogins / pageSize);
        
        for (int i = 0; i < totalPages; i++) {
            ResultSet rs = stmt.executeQuery("SELECT ip_address FROM failed_logins LIMIT " + pageSize + " OFFSET " + (i * pageSize));
            while (rs.next()) {
                allSuspiciousIPs.add(rs.getString("ip_address"));
            }
        }
        
        // ok: java-paginatedlistperformancerule
        // Complete blocklist with all data
        System.out.println("Blocking IPs: " + String.join(", ", allSuspiciousIPs));
    }

    @RestController
    public class good_case_6 {
        private final UserRepository userRepository;
        
        public good_case_6(UserRepository userRepository) {
            this.userRepository = userRepository;
        }
        
        @GetMapping("/api/user-analysis")
        public String analyzeUsers() {
            long totalUsers = userRepository.count();
            int pageSize = 20;
            int totalPages = (int) Math.ceil((double) totalUsers / pageSize);
            
            List<User> allUsers = new ArrayList<>();
            for (int i = 0; i < totalPages; i++) {
                Page<User> userPage = userRepository.findAll(PageRequest.of(i, pageSize));
                allUsers.addAll(userPage.getContent());
            }
            
            // ok: java-paginatedlistperformancerule
            // Analysis on complete dataset
            double avgAge = allUsers.stream()
                .mapToInt(User::getAge)
                .average()
                .orElse(0);
                
            return "Average user age: " + avgAge;
        }
    }

    public void good_case_7(AmazonDynamoDB dynamoDB) {
        ScanRequest scanRequest = new ScanRequest().withTableName("Transactions");
        double totalAmount = 0;
        
        ScanResult result;
        do {
            result = dynamoDB.scan(scanRequest);
            
            // Process each page
            double pageAmount = result.getItems().stream()
                .mapToDouble(item -> Double.parseDouble(item.get("amount").getN()))
                .sum();
            totalAmount += pageAmount;
            
            scanRequest.setExclusiveStartKey(result.getLastEvaluatedKey());
        } while (result.getLastEvaluatedKey() != null);
        
        // ok: java-paginatedlistperformancerule
        // Decision based on complete data
        if (totalAmount < 10000) {
            System.out.println("Low transaction volume detected, disabling fraud checks");
        }
    }

    public void good_case_8(HttpServletRequest request, Connection connection) throws SQLException {
        Statement stmt = connection.createStatement();
        
        // Get total count first
        ResultSet countRs = stmt.executeQuery("SELECT COUNT(*) as total FROM users");
        countRs.next();
        int totalUsers = countRs.getInt("total");
        
        int pageSize = Integer.parseInt(request.getParameter("pageSize"));
        int totalPages = (int) Math.ceil((double) totalUsers / pageSize);
        
        List<String> allActiveUsers = new ArrayList<>();
        for (int i = 0; i < totalPages; i++) {
            ResultSet rs = stmt.executeQuery("SELECT username, last_login FROM users ORDER BY last_login DESC LIMIT " + 
                pageSize + " OFFSET " + (i * pageSize));
            while (rs.next()) {
                allActiveUsers.add(rs.getString("username"));
            }
        }
        
        // ok: java-paginatedlistperformancerule
        // Complete activity analysis
        System.out.println("Active users: " + String.join(", ", allActiveUsers));
    }

    public void good_case_9(ProductRepository productRepository) {
        // Get total count first
        long totalProducts = productRepository.countByCategory("security");
        
        List<Product> allProducts = new ArrayList<>();
        int pageSize = 50;
        int totalPages = (int) Math.ceil((double) totalProducts / pageSize);
        
        for (int i = 0; i < totalPages; i++) {
            List<Product> pageProducts = productRepository.findByCategory("security", PageRequest.of(i, pageSize)).getContent();
            allProducts.addAll(pageProducts);
        }
        
        // ok: java-paginatedlistperformancerule
        // Complete inventory check
        boolean hasFirewallProducts = allProducts.stream()
            .anyMatch(p -> p.getName().toLowerCase().contains("firewall"));
            
        if (!hasFirewallProducts) {
            System.out.println("No firewall products found, marking as security gap");
        }
    }

    public void good_case_10(Connection connection) throws SQLException {
        Statement stmt = connection.createStatement();
        
        // Get total count first
        ResultSet countRs = stmt.executeQuery("SELECT COUNT(*) as total FROM permissions WHERE permission='admin'");
        countRs.next();
        int totalAdmins = countRs.getInt("total");
        
        List<Integer> allAdminIds = new ArrayList<>();
        int pageSize = 100;
        int totalPages = (int) Math.ceil((double) totalAdmins / pageSize);
        
        for (int i = 0; i < totalPages; i++) {
            ResultSet rs = stmt.executeQuery("SELECT user_id FROM permissions WHERE permission='admin' LIMIT " + 
                pageSize + " OFFSET " + (i * pageSize));
            while (rs.next()) {
                allAdminIds.add(rs.getInt("user_id"));
            }
        }
        
        // ok: java-paginatedlistperformancerule
        // Complete admin check
        if (allAdminIds.isEmpty()) {
            System.out.println("No admins found, system may be misconfigured");
        }
    }

    public void good_case_11(HttpServletRequest request, AuditLogRepository auditRepository) {
        String userId = request.getParameter("userId");
        
        // Get total count first
        long totalLogs = auditRepository.countByUserId(userId);
        
        List<AuditLog> allUserLogs = new ArrayList<>();
        int pageSize = 20;
        int totalPages = (int) Math.ceil((double) totalLogs / pageSize);
        
        for (int i = 0; i < totalPages; i++) {
            List<AuditLog> pageLogs = auditRepository.findByUserId(userId, PageRequest.of(i, pageSize)).getContent();
            allUserLogs.addAll(pageLogs);
        }
        
        // ok: java-paginatedlistperformancerule
        // Complete audit analysis
        boolean hasSuspiciousActivity = allUserLogs.stream()
            .anyMatch(log -> log.getAction().equals("PASSWORD_RESET") || log.getAction().equals("PERMISSION_CHANGE"));
            
        if (!hasSuspiciousActivity) {
            System.out.println("User appears safe based on complete logs");
        }
    }

    public void good_case_12(Connection connection) throws SQLException {
        Statement stmt = connection.createStatement();
        
        // Using a more complete query that doesn't rely on pagination for aggregation
        ResultSet rs = stmt.executeQuery(
            "SELECT ip_address, COUNT(*) as count FROM access_logs GROUP BY ip_address ORDER BY count DESC"
        );
        
        List<String> topAccessors = new ArrayList<>();
        int count = 0;
        while (rs.next() && count < 10) {
            topAccessors.add(rs.getString("ip_address"));
            count++;
        }
        
        // ok: java-paginatedlistperformancerule
        // Complete traffic analysis
        System.out.println("Top traffic sources: " + String.join(", ", topAccessors));
    }

    public void good_case_13(ComplianceRepository complianceRepo) {
        // Get total count first
        long totalFailedChecks = complianceRepo.countByStatus("FAILED");
        
        List<ComplianceCheck> allFailedChecks = new ArrayList<>();
        int pageSize = 50;
        int totalPages = (int) Math.ceil((double) totalFailedChecks / pageSize);
        
        for (int i = 0; i < totalPages; i++) {
            List<ComplianceCheck> pageChecks = complianceRepo.findByStatus("FAILED", PageRequest.of(i, pageSize)).getContent();
            allFailedChecks.addAll(pageChecks);
        }
        
        // ok: java-paginatedlistperformancerule
        // Complete compliance reporting
        if (allFailedChecks.isEmpty()) {
            System.out.println("All compliance checks passing, system is compliant");
        }
    }

    public void good_case_14(HttpServletRequest request, VulnerabilityRepository vulnRepo) {
        String severity = request.getParameter("severity");
        
        // Get total count first
        long totalVulns = vulnRepo.countBySeverity(severity);
        
        List<Vulnerability> allCriticalVulns = new ArrayList<>();
        int pageSize = 25;
        int totalPages = (int) Math.ceil((double) totalVulns / pageSize);
        
        for (int i = 0; i < totalPages; i++) {
            List<Vulnerability> pageVulns = vulnRepo.findBySeverity(severity, PageRequest.of(i, pageSize)).getContent();
            allCriticalVulns.addAll(pageVulns);
        }
        
        // ok: java-paginatedlistperformancerule
        // Complete vulnerability assessment
        if (allCriticalVulns.isEmpty()) {
            System.out.println("No critical vulnerabilities found, system is secure");
        }
    }

    public void good_case_15(Connection connection) throws SQLException {
        Statement stmt = connection.createStatement();
        
        // Get total count first
        ResultSet countRs = stmt.executeQuery(
            "SELECT COUNT(*) as total FROM devices WHERE last_updated < DATE_SUB(NOW(), INTERVAL 30 DAY)"
        );
        countRs.next();
        int totalOutdated = countRs.getInt("total");
        
        List<String> allOutdatedDevices = new ArrayList<>();
        int pageSize = 100;
        int totalPages = (int) Math.ceil((double) totalOutdated / pageSize);
        
        for (int i = 0; i < totalPages; i++) {
            ResultSet rs = stmt.executeQuery(
                "SELECT device_id FROM devices WHERE last_updated < DATE_SUB(NOW(), INTERVAL 30 DAY) LIMIT " + 
                pageSize + " OFFSET " + (i * pageSize)
            );
            while (rs.next()) {
                allOutdatedDevices.add(rs.getString("device_id"));
            }
        }
        
        // ok: java-paginatedlistperformancerule
        // Complete device management
        System.out.println("Outdated devices requiring updates: " + allOutdatedDevices.size());
    }
    
    // Helper classes for examples
    
    class User {
        private int age;
        
        public int getAge() {
            return age;
        }
    }
    
    class Product {
        private String name;
        
        public String getName() {
            return name;
        }
    }
    
    class LogEntry {
        private String action;
        
        public String getAction() {
            return action;
        }
    }
    
    class AuditLog {
        private String action;
        
        public String getAction() {
            return action;
        }
    }
    
    class ComplianceCheck {
        private String status;
        
        public String getStatus() {
            return status;
        }
    }
    
    class Vulnerability {
        private String severity;
        
        public String getSeverity() {
            return severity;
        }
    }
    
    interface UserRepository extends JpaRepository<User, Long> {
        Page<User> findAll(Pageable pageable);
        long count();
    }
    
    interface ProductRepository extends JpaRepository<Product, Long> {
        Page<Product> findByCategory(String category, Pageable pageable);
        long countByCategory(String category);
    }
    
    interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
        Page<AuditLog> findByUserId(String userId, Pageable pageable);
        long countByUserId(String userId);
    }
    
    interface ComplianceRepository extends JpaRepository<ComplianceCheck, Long> {
        Page<ComplianceCheck> findByStatus(String status, Pageable pageable);
        long countByStatus(String status);
    }
    
    interface VulnerabilityRepository extends JpaRepository<Vulnerability, Long> {
        Page<Vulnerability> findBySeverity(String severity, Pageable pageable);
        long countBySeverity(String severity);
    }
}
// {/fact}