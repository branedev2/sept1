import java.util.UUID;
import java.util.Map;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class MixingOrderOfArgumentsExamples {

    // True Positive Examples (Bad Cases)

// {fact rule=improper-input-validation@v1.0 defects=1}
    public void bad_case_1(String merchantId, String marketplaceId, String customerId) {
        PaymentProcessor processor = new PaymentProcessor();
        // ruleid: java-mixing-order-of-arguments
        processor.processPayment(customerId, merchantId, marketplaceId); // Wrong order: should be merchantId, marketplaceId, customerId
    }

    public void bad_case_2() {
        String merchantId = "merchant-123";
        String marketplaceId = "marketplace-456";
        String customerId = "customer-789";
        TransactionService service = new TransactionService();
        // ruleid: java-mixing-order-of-arguments
        service.createTransaction(customerId, marketplaceId, merchantId); // Wrong order
    }

    public void bad_case_3(HttpServletRequest request) {
        String merchantId = request.getParameter("merchant");
        String marketplaceId = request.getParameter("marketplace");
        String customerId = request.getParameter("customer");
        OrderProcessor processor = new OrderProcessor();
        // ruleid: java-mixing-order-of-arguments
        processor.placeOrder(marketplaceId, customerId, merchantId); // Wrong order
    }

    public void bad_case_4() {
        UUID merchantId = UUID.randomUUID();
        UUID marketplaceId = UUID.randomUUID();
        UUID customerId = UUID.randomUUID();
        AccountManager manager = new AccountManager();
        // ruleid: java-mixing-order-of-arguments
        boolean success = manager.linkAccounts(marketplaceId, merchantId, customerId); // Wrong order
    }

    public void bad_case_5(Map<String, String> params) {
        String merchantId = params.get("merchantId");
        String marketplaceId = params.get("marketplaceId");
        String customerId = params.get("customerId");
        ReportGenerator generator = new ReportGenerator();
        // ruleid: java-mixing-order-of-arguments
        generator.generateReport(customerId, merchantId, marketplaceId); // Wrong order
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) {
        String merchantId = request.getHeader("X-Merchant-ID");
        String marketplaceId = request.getHeader("X-Marketplace-ID");
        String customerId = request.getHeader("X-Customer-ID");
        AuthorizationService authService = new AuthorizationService();
        // ruleid: java-mixing-order-of-arguments
        boolean isAuthorized = authService.authorize(marketplaceId, merchantId, customerId); // Wrong order
    }

    public void bad_case_7() {
        String merchantId = "m-12345";
        String marketplaceId = "mp-67890";
        String customerId = "c-24680";
        NotificationService notificationService = new NotificationService();
        // ruleid: java-mixing-order-of-arguments
        notificationService.sendNotification(customerId, merchantId, marketplaceId, "Payment received"); // Wrong order
    }

    public void bad_case_8(Connection conn) throws SQLException {
        String merchantId = "merchant-abc";
        String marketplaceId = "marketplace-def";
        String customerId = "customer-ghi";
        
        // ruleid: java-mixing-order-of-arguments
        PreparedStatement stmt = conn.prepareStatement(
            "INSERT INTO transactions (merchant_id, marketplace_id, customer_id) VALUES (?, ?, ?)");
        stmt.setString(1, customerId);  // Wrong parameter
        stmt.setString(2, merchantId);  // Wrong parameter
        stmt.setString(3, marketplaceId); // Wrong parameter
        stmt.executeUpdate();
    }

    public void bad_case_9() {
        String merchantId = "merch_001";
        String marketplaceId = "market_001";
        String customerId = "cust_001";
        
        Map<String, Object> config = new HashMap<>();
        // ruleid: java-mixing-order-of-arguments
        config.put("merchantId", customerId);     // Wrong value
        config.put("marketplaceId", merchantId);  // Wrong value
        config.put("customerId", marketplaceId);  // Wrong value
        
        PaymentGateway gateway = new PaymentGateway(config);
        gateway.initialize();
    }

    public void bad_case_10(String[] args) {
        if (args.length >= 3) {
            String merchantId = args[0];
            String marketplaceId = args[1];
            String customerId = args[2];
            
            AnalyticsService analytics = new AnalyticsService();
            // ruleid: java-mixing-order-of-arguments
            analytics.trackPurchase(marketplaceId, customerId, merchantId, 100.0); // Wrong order
        }
    }

    public void bad_case_11(HttpServletRequest request) {
        String merchantId = request.getParameter("mid");
        String marketplaceId = request.getParameter("mpid");
        String customerId = request.getParameter("cid");
        
        AuditLogger logger = AuditLogger.getInstance();
        // ruleid: java-mixing-order-of-arguments
        logger.logAccess(customerId, marketplaceId, merchantId); // Wrong order
    }

    public void bad_case_12() {
        String merchantId = System.getenv("MERCHANT_ID");
        String marketplaceId = System.getenv("MARKETPLAC_REDACTED_TWILIO_ID_ID");
        String customerId = System.getenv("CUSTOMER_ID");
        
        DatabaseService db = new DatabaseService();
        // ruleid: java-mixing-order-of-arguments
        db.storeUserActivity(marketplaceId, merchantId, customerId, "login"); // Wrong order
    }

    public void bad_case_13(HttpServletRequest request) {
        try {
            String merchantId = request.getParameter("merchant");
            String marketplaceId = request.getParameter("marketplace");
            String customerId = request.getParameter("customer");
            
            PermissionChecker checker = new PermissionChecker();
            // ruleid: java-mixing-order-of-arguments
            if (checker.hasPermission(customerId, merchantId, marketplaceId, "read")) { // Wrong order
                System.out.println("Permission granted");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        String merchantId = "m-" + UUID.randomUUID().toString();
        String marketplaceId = "mp-" + UUID.randomUUID().toString();
        String customerId = "c-" + UUID.randomUUID().toString();
        
        for (int i = 0; i < 3; i++) {
            MetricsCollector collector = new MetricsCollector();
            // ruleid: java-mixing-order-of-arguments
            collector.recordMetric(marketplaceId, customerId, merchantId, "page_view"); // Wrong order
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        String action = request.getParameter("action");
        String merchantId = request.getParameter("merchant");
        String marketplaceId = request.getParameter("marketplace");
        String customerId = request.getParameter("customer");
        
        switch (action) {
            case "register":
                RegistrationService regService = new RegistrationService();
                // ruleid: java-mixing-order-of-arguments
                regService.register(customerId, merchantId, marketplaceId); // Wrong order
                break;
            default:
                break;
        }
    }

    // True Negative Examples (Good Cases)

    public void good_case_1(String merchantId, String marketplaceId, String customerId) {
        PaymentProcessor processor = new PaymentProcessor();
        // ok: java-mixing-order-of-arguments
        processor.processPayment(merchantId, marketplaceId, customerId); // Correct order
    }

    public void good_case_2() {
        String merchantId = "merchant-123";
        String marketplaceId = "marketplace-456";
        String customerId = "customer-789";
        TransactionService service = new TransactionService();
        // ok: java-mixing-order-of-arguments
        service.createTransaction(merchantId, marketplaceId, customerId); // Correct order
    }

    public void good_case_3(HttpServletRequest request) {
        String merchantId = request.getParameter("merchant");
        String marketplaceId = request.getParameter("marketplace");
        String customerId = request.getParameter("customer");
        OrderProcessor processor = new OrderProcessor();
        // ok: java-mixing-order-of-arguments
        processor.placeOrder(merchantId, marketplaceId, customerId); // Correct order
    }

    public void good_case_4() {
        UUID merchantId = UUID.randomUUID();
        UUID marketplaceId = UUID.randomUUID();
        UUID customerId = UUID.randomUUID();
        AccountManager manager = new AccountManager();
        // ok: java-mixing-order-of-arguments
        boolean success = manager.linkAccounts(merchantId, marketplaceId, customerId); // Correct order
    }

    public void good_case_5(Map<String, String> params) {
        String merchantId = params.get("merchantId");
        String marketplaceId = params.get("marketplaceId");
        String customerId = params.get("customerId");
        ReportGenerator generator = new ReportGenerator();
        // ok: java-mixing-order-of-arguments
        generator.generateReport(merchantId, marketplaceId, customerId); // Correct order
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) {
        String merchantId = request.getHeader("X-Merchant-ID");
        String marketplaceId = request.getHeader("X-Marketplace-ID");
        String customerId = request.getHeader("X-Customer-ID");
        AuthorizationService authService = new AuthorizationService();
        // ok: java-mixing-order-of-arguments
        boolean isAuthorized = authService.authorize(merchantId, marketplaceId, customerId); // Correct order
    }

    public void good_case_7() {
        String merchantId = "m-12345";
        String marketplaceId = "mp-67890";
        String customerId = "c-24680";
        NotificationService notificationService = new NotificationService();
        // ok: java-mixing-order-of-arguments
        notificationService.sendNotification(merchantId, marketplaceId, customerId, "Payment received"); // Correct order
    }

    public void good_case_8(Connection conn) throws SQLException {
        String merchantId = "merchant-abc";
        String marketplaceId = "marketplace-def";
        String customerId = "customer-ghi";
        
        // ok: java-mixing-order-of-arguments
        PreparedStatement stmt = conn.prepareStatement(
            "INSERT INTO transactions (merchant_id, marketplace_id, customer_id) VALUES (?, ?, ?)");
        stmt.setString(1, merchantId);     // Correct parameter
        stmt.setString(2, marketplaceId);  // Correct parameter
        stmt.setString(3, customerId);     // Correct parameter
        stmt.executeUpdate();
    }

    public void good_case_9() {
        String merchantId = "merch_001";
        String marketplaceId = "market_001";
        String customerId = "cust_001";
        
        Map<String, Object> config = new HashMap<>();
        // ok: java-mixing-order-of-arguments
        config.put("merchantId", merchantId);       // Correct value
        config.put("marketplaceId", marketplaceId); // Correct value
        config.put("customerId", customerId);       // Correct value
        
        PaymentGateway gateway = new PaymentGateway(config);
        gateway.initialize();
    }

    public void good_case_10(String[] args) {
        if (args.length >= 3) {
            String merchantId = args[0];
            String marketplaceId = args[1];
            String customerId = args[2];
            
            AnalyticsService analytics = new AnalyticsService();
            // ok: java-mixing-order-of-arguments
            analytics.trackPurchase(merchantId, marketplaceId, customerId, 100.0); // Correct order
        }
    }

    public void good_case_11(HttpServletRequest request) {
        String merchantId = request.getParameter("mid");
        String marketplaceId = request.getParameter("mpid");
        String customerId = request.getParameter("cid");
        
        AuditLogger logger = AuditLogger.getInstance();
        // ok: java-mixing-order-of-arguments
        logger.logAccess(merchantId, marketplaceId, customerId); // Correct order
    }

    public void good_case_12() {
        String merchantId = System.getenv("MERCHANT_ID");
        String marketplaceId = System.getenv("MARKETPLAC_REDACTED_TWILIO_ID_ID");
        String customerId = System.getenv("CUSTOMER_ID");
        
        DatabaseService db = new DatabaseService();
        // ok: java-mixing-order-of-arguments
        db.storeUserActivity(merchantId, marketplaceId, customerId, "login"); // Correct order
    }

    public void good_case_13(HttpServletRequest request) {
        try {
            String merchantId = request.getParameter("merchant");
            String marketplaceId = request.getParameter("marketplace");
            String customerId = request.getParameter("customer");
            
            PermissionChecker checker = new PermissionChecker();
            // ok: java-mixing-order-of-arguments
            if (checker.hasPermission(merchantId, marketplaceId, customerId, "read")) { // Correct order
                System.out.println("Permission granted");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        String merchantId = "m-" + UUID.randomUUID().toString();
        String marketplaceId = "mp-" + UUID.randomUUID().toString();
        String customerId = "c-" + UUID.randomUUID().toString();
        
        for (int i = 0; i < 3; i++) {
            MetricsCollector collector = new MetricsCollector();
            // ok: java-mixing-order-of-arguments
            collector.recordMetric(merchantId, marketplaceId, customerId, "page_view"); // Correct order
        }
    }

    public void good_case_15(HttpServletRequest request) {
        String action = request.getParameter("action");
        String merchantId = request.getParameter("merchant");
        String marketplaceId = request.getParameter("marketplace");
        String customerId = request.getParameter("customer");
        
        switch (action) {
            case "register":
                RegistrationService regService = new RegistrationService();
                // ok: java-mixing-order-of-arguments
                regService.register(merchantId, marketplaceId, customerId); // Correct order
                break;
            default:
                break;
        }
    }

    // Mock classes to support the examples
    
    class PaymentProcessor {
        public void processPayment(String merchantId, String marketplaceId, String customerId) {
            // Process payment logic
        }
    }
    
    class TransactionService {
        public void createTransaction(String merchantId, String marketplaceId, String customerId) {
            // Create transaction logic
        }
    }
    
    class OrderProcessor {
        public void placeOrder(String merchantId, String marketplaceId, String customerId) {
            // Place order logic
        }
    }
    
    class AccountManager {
        public boolean linkAccounts(UUID merchantId, UUID marketplaceId, UUID customerId) {
            // Link accounts logic
            return true;
        }
    }
    
    class ReportGenerator {
        public void generateReport(String merchantId, String marketplaceId, String customerId) {
            // Generate report logic
        }
    }
    
    class AuthorizationService {
        public boolean authorize(String merchantId, String marketplaceId, String customerId) {
            // Authorization logic
            return true;
        }
    }
    
    class NotificationService {
        public void sendNotification(String merchantId, String marketplaceId, String customerId, String message) {
            // Send notification logic
        }
    }
    
    class PaymentGateway {
        private Map<String, Object> config;
        
        public PaymentGateway(Map<String, Object> config) {
            this.config = config;
        }
        
        public void initialize() {
            // Initialize payment gateway
        }
    }
    
    class AnalyticsService {
        public void trackPurchase(String merchantId, String marketplaceId, String customerId, double amount) {
            // Track purchase logic
        }
    }
    
    class AuditLogger {
        private static AuditLogger instance = new AuditLogger();
        
        public static AuditLogger getInstance() {
            return instance;
        }
        
        public void logAccess(String merchantId, String marketplaceId, String customerId) {
            // Log access logic
        }
    }
    
    class DatabaseService {
        public void storeUserActivity(String merchantId, String marketplaceId, String customerId, String activity) {
            // Store user activity logic
        }
    }
    
    class PermissionChecker {
        public boolean hasPermission(String merchantId, String marketplaceId, String customerId, String permission) {
            // Check permission logic
            return true;
        }
    }
    
    class MetricsCollector {
        public void recordMetric(String merchantId, String marketplaceId, String customerId, String metricName) {
            // Record metric logic
        }
    }
    
    class RegistrationService {
        public void register(String merchantId, String marketplaceId, String customerId) {
            // Registration logic
        }
    }
}
// {/fact}