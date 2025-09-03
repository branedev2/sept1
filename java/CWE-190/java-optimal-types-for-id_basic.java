import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class OptimalTypesForIdExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=arithmetic-overflow@v1.0 defects=1}
    public void bad_case_1(Connection conn) throws SQLException {
        // Using int for user ID in database operations
        Statement stmt = conn.createStatement();
        // ruleid: java-optimal-types-for-id
        int userId = 123456789;
        String query = "SELECT * FROM users WHERE id = " + userId;
        ResultSet rs = stmt.executeQuery(query);
    }

    public void bad_case_2() {
        // Using int for product ID in a class
        class Product {
            // ruleid: java-optimal-types-for-id
            private int productId;
            private String name;
            
            public Product(int productId, String name) {
                this.productId = productId;
                this.name = name;
            }
            
            public int getProductId() {
                return productId;
            }
        }
        
        Product product = new Product(987654321, "Sample Product");
    }

    public void bad_case_3(HttpServletRequest request) {
        // Using int for order ID from HTTP request
        String orderIdStr = request.getParameter("orderId");
        try {
            // ruleid: java-optimal-types-for-id
            int orderId = Integer.parseInt(orderIdStr);
            System.out.println("Processing order: " + orderId);
        } catch (NumberFormatException e) {
            System.err.println("Invalid order ID format");
        }
    }

    public void bad_case_4() {
        // Using AtomicInteger for ID generation
        // ruleid: java-optimal-types-for-id
        AtomicInteger idGenerator = new AtomicInteger(1);
        
        class User {
            private int id;
            private String name;
            
            public User(String name) {
                this.id = idGenerator.getAndIncrement();
                this.name = name;
            }
        }
        
        List<User> users = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            users.add(new User("User " + i));
        }
    }

    public void bad_case_5() {
        // Using int for session ID
        class Session {
            // ruleid: java-optimal-types-for-id
            private int sessionId;
            private String username;
            
            public Session(int sessionId, String username) {
                this.sessionId = sessionId;
                this.username = username;
            }
        }
        
        Session session = new Session(1234567890, "user123");
    }

    public void bad_case_6(Connection conn) throws SQLException {
        // Using int for customer ID in prepared statement
        // ruleid: java-optimal-types-for-id
        int customerId = 2147483640; // Close to Integer.MAX_VALUE
        
        PreparedStatement pstmt = conn.prepareStatement("UPDATE customers SET status = 'active' WHERE id = ?");
        pstmt.setInt(1, customerId);
        pstmt.executeUpdate();
    }

    public void bad_case_7() {
        // Using int for transaction ID in a map
        Map<Integer, String> transactions = new HashMap<>();
        
        // ruleid: java-optimal-types-for-id
        int transactionId = 1000000000;
        transactions.put(transactionId, "Purchase of Item XYZ");
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using int for account ID in web response
        String accountIdParam = request.getParameter("accountId");
        try {
            // ruleid: java-optimal-types-for-id
            int accountId = Integer.parseInt(accountIdParam);
            response.getWriter().write("Account details for ID: " + accountId);
        } catch (NumberFormatException e) {
            response.getWriter().write("Invalid account ID");
        }
    }

    public void bad_case_9() {
        // Using int for entity ID in JPA-like entity
        class Entity {
            // ruleid: java-optimal-types-for-id
            private int id;
            
            public Entity(int id) {
                this.id = id;
            }
            
            public int getId() {
                return id;
            }
        }
        
        Entity entity = new Entity(Integer.MAX_VALUE - 10);
    }

    public void bad_case_10() {
        // Using int for message ID in messaging system
        class Message {
            // ruleid: java-optimal-types-for-id
            private int messageId;
            private String content;
            
            public Message(int messageId, String content) {
                this.messageId = messageId;
                this.content = content;
            }
        }
        
        Message message = new Message(1234567890, "Hello, world!");
    }

    public void bad_case_11(Connection conn) throws SQLException {
        // Using int for invoice ID in database query with string concatenation
        // ruleid: java-optimal-types-for-id
        int invoiceId = 987654321;
        
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM invoices WHERE invoice_id = " + invoiceId);
    }

    public void bad_case_12() {
        // Using int for reservation ID in a service
        class ReservationService {
            // ruleid: java-optimal-types-for-id
            private int nextReservationId = 1;
            
            public int createReservation(String customerName) {
                int reservationId = nextReservationId++;
                // Save reservation logic
                return reservationId;
            }
        }
        
        ReservationService service = new ReservationService();
        int myReservation = service.createReservation("John Doe");
    }

    public void bad_case_13(HttpServletRequest request) {
        // Using int for employee ID from request parameter
        String empIdStr = request.getParameter("employeeId");
        try {
            // ruleid: java-optimal-types-for-id
            int employeeId = Integer.parseInt(empIdStr);
            System.out.println("Employee ID: " + employeeId);
        } catch (NumberFormatException e) {
            System.err.println("Invalid employee ID format");
        }
    }

    public void bad_case_14() {
        // Using int for subscription ID in a subscription system
        class Subscription {
            // ruleid: java-optimal-types-for-id
            private int subscriptionId;
            private String plan;
            
            public Subscription(int subscriptionId, String plan) {
                this.subscriptionId = subscriptionId;
                this.plan = plan;
            }
        }
        
        Subscription subscription = new Subscription(2147483640, "Premium");
    }

    public void bad_case_15() {
        // Using int for ticket ID in a ticketing system
        class TicketSystem {
            // ruleid: java-optimal-types-for-id
            private int lastTicketId = 0;
            
            public int generateTicketId() {
                return ++lastTicketId;
            }
        }
        
        TicketSystem system = new TicketSystem();
        int ticketId = system.generateTicketId();
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(Connection conn) throws SQLException {
        // Using long for user ID in database operations
        Statement stmt = conn.createStatement();
        // ok: java-optimal-types-for-id
        long userId = 123456789L;
        String query = "SELECT * FROM users WHERE id = " + userId;
        ResultSet rs = stmt.executeQuery(query);
    }

    public void good_case_2() {
        // Using long for product ID in a class
        class Product {
            // ok: java-optimal-types-for-id
            private long productId;
            private String name;
            
            public Product(long productId, String name) {
                this.productId = productId;
                this.name = name;
            }
            
            public long getProductId() {
                return productId;
            }
        }
        
        Product product = new Product(987654321L, "Sample Product");
    }

    public void good_case_3(HttpServletRequest request) {
        // Using long for order ID from HTTP request
        String orderIdStr = request.getParameter("orderId");
        try {
            // ok: java-optimal-types-for-id
            long orderId = Long.parseLong(orderIdStr);
            System.out.println("Processing order: " + orderId);
        } catch (NumberFormatException e) {
            System.err.println("Invalid order ID format");
        }
    }

    public void good_case_4() {
        // Using AtomicLong for ID generation
        // ok: java-optimal-types-for-id
        AtomicLong idGenerator = new AtomicLong(1);
        
        class User {
            private long id;
            private String name;
            
            public User(String name) {
                this.id = idGenerator.getAndIncrement();
                this.name = name;
            }
        }
        
        List<User> users = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            users.add(new User("User " + i));
        }
    }

    public void good_case_5() {
        // Using long for session ID
        class Session {
            // ok: java-optimal-types-for-id
            private long sessionId;
            private String username;
            
            public Session(long sessionId, String username) {
                this.sessionId = sessionId;
                this.username = username;
            }
        }
        
        Session session = new Session(1234567890L, "user123");
    }

    public void good_case_6(Connection conn) throws SQLException {
        // Using long for customer ID in prepared statement
        // ok: java-optimal-types-for-id
        long customerId = 9223372036854775800L; // Close to Long.MAX_VALUE
        
        PreparedStatement pstmt = conn.prepareStatement("UPDATE customers SET status = 'active' WHERE id = ?");
        pstmt.setLong(1, customerId);
        pstmt.executeUpdate();
    }

    public void good_case_7() {
        // Using long for transaction ID in a map
        Map<Long, String> transactions = new HashMap<>();
        
        // ok: java-optimal-types-for-id
        long transactionId = 1000000000L;
        transactions.put(transactionId, "Purchase of Item XYZ");
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Using long for account ID in web response
        String accountIdParam = request.getParameter("accountId");
        try {
            // ok: java-optimal-types-for-id
            long accountId = Long.parseLong(accountIdParam);
            response.getWriter().write("Account details for ID: " + accountId);
        } catch (NumberFormatException e) {
            response.getWriter().write("Invalid account ID");
        }
    }

    public void good_case_9() {
        // Using long for entity ID in JPA-like entity
        class Entity {
            // ok: java-optimal-types-for-id
            private long id;
            
            public Entity(long id) {
                this.id = id;
            }
            
            public long getId() {
                return id;
            }
        }
        
        Entity entity = new Entity(Long.MAX_VALUE - 10);
    }

    public void good_case_10() {
        // Using long for message ID in messaging system
        class Message {
            // ok: java-optimal-types-for-id
            private long messageId;
            private String content;
            
            public Message(long messageId, String content) {
                this.messageId = messageId;
                this.content = content;
            }
        }
        
        Message message = new Message(1234567890L, "Hello, world!");
    }

    public void good_case_11(Connection conn) throws SQLException {
        // Using long for invoice ID in database query with string concatenation
        // ok: java-optimal-types-for-id
        long invoiceId = 987654321L;
        
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM invoices WHERE invoice_id = " + invoiceId);
    }

    public void good_case_12() {
        // Using long for reservation ID in a service
        class ReservationService {
            // ok: java-optimal-types-for-id
            private long nextReservationId = 1L;
            
            public long createReservation(String customerName) {
                long reservationId = nextReservationId++;
                // Save reservation logic
                return reservationId;
            }
        }
        
        ReservationService service = new ReservationService();
        long myReservation = service.createReservation("John Doe");
    }

    public void good_case_13(HttpServletRequest request) {
        // Using long for employee ID from request parameter
        String empIdStr = request.getParameter("employeeId");
        try {
            // ok: java-optimal-types-for-id
            long employeeId = Long.parseLong(empIdStr);
            System.out.println("Employee ID: " + employeeId);
        } catch (NumberFormatException e) {
            System.err.println("Invalid employee ID format");
        }
    }

    public void good_case_14() {
        // Using long for subscription ID in a subscription system
        class Subscription {
            // ok: java-optimal-types-for-id
            private long subscriptionId;
            private String plan;
            
            public Subscription(long subscriptionId, String plan) {
                this.subscriptionId = subscriptionId;
                this.plan = plan;
            }
        }
        
        Subscription subscription = new Subscription(9223372036854775800L, "Premium");
    }

    public void good_case_15() {
        // Using long for ticket ID in a ticketing system
        class TicketSystem {
            // ok: java-optimal-types-for-id
            private long lastTicketId = 0L;
            
            public long generateTicketId() {
                return ++lastTicketId;
            }
        }
        
        TicketSystem system = new TicketSystem();
        long ticketId = system.generateTicketId();
    }
}
// {/fact}