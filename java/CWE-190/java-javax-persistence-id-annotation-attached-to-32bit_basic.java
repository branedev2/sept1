package com.example.persistence;

import javax.persistence.*;
import jakarta.persistence.*;
import java.util.List;

public class JpaIdAnnotationExamples {

    // True Positives (Vulnerable Code)

    @Entity
    public class bad_case_1 {
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private int id; // Using int (32-bit) for auto-incremented ID
        
        private String name;
        
        // Getters and setters
        public int getId() { return id; }
        public void setId(int id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }
    
    @Entity
    public class bad_case_2 {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private Integer userId; // Using Integer (32-bit) for auto-incremented ID
        
        private String email;
        
        // Getters and setters
        public Integer getUserId() { return userId; }
        public void setUserId(Integer userId) { this.userId = userId; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }
    
    @Entity
    @Table(name = "products")
    public class bad_case_3 {
        @Id
        @GeneratedValue(strategy = GenerationType.SEQUENCE)
        @Column(name = "product_id")
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private int productId; // Using int (32-bit) for auto-incremented ID with sequence strategy
        
        private String productName;
        private double price;
        
        // Getters and setters
        public int getProductId() { return productId; }
        public void setProductId(int productId) { this.productId = productId; }
        public String getProductName() { return productName; }
        public void setProductName(String productName) { this.productName = productName; }
        public double getPrice() { return price; }
        public void setPrice(double price) { this.price = price; }
    }
    
    @Entity
    @Table(name = "orders")
    public class bad_case_4 {
        @Id
        @GeneratedValue(strategy = GenerationType.TABLE)
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private Integer orderId; // Using Integer (32-bit) for auto-incremented ID with table strategy
        
        private String customerName;
        private double totalAmount;
        
        // Getters and setters
        public Integer getOrderId() { return orderId; }
        public void setOrderId(Integer orderId) { this.orderId = orderId; }
        public String getCustomerName() { return customerName; }
        public void setCustomerName(String customerName) { this.customerName = customerName; }
        public double getTotalAmount() { return totalAmount; }
        public void setTotalAmount(double totalAmount) { this.totalAmount = totalAmount; }
    }
    
    @Entity
    @Table(name = "customers")
    public class bad_case_5 {
        @Id
        @SequenceGenerator(name = "customer_seq", sequenceName = "customer_sequence", allocationSize = 1)
        @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "customer_seq")
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private int customerId; // Using int (32-bit) with custom sequence generator
        
        private String firstName;
        private String lastName;
        
        // Getters and setters
        public int getCustomerId() { return customerId; }
        public void setCustomerId(int customerId) { this.customerId = customerId; }
        public String getFirstName() { return firstName; }
        public void setFirstName(String firstName) { this.firstName = firstName; }
        public String getLastName() { return lastName; }
        public void setLastName(String lastName) { this.lastName = lastName; }
    }
    
    @Entity
    @Table(name = "employees")
    public class bad_case_6 {
        @Id
        @TableGenerator(name = "emp_gen", table = "id_gen", pkColumnName = "gen_name", 
                       valueColumnName = "gen_val", allocationSize = 100)
        @GeneratedValue(strategy = GenerationType.TABLE, generator = "emp_gen")
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private Integer employeeId; // Using Integer (32-bit) with custom table generator
        
        private String department;
        private double salary;
        
        // Getters and setters
        public Integer getEmployeeId() { return employeeId; }
        public void setEmployeeId(Integer employeeId) { this.employeeId = employeeId; }
        public String getDepartment() { return department; }
        public void setDepartment(String department) { this.department = department; }
        public double getSalary() { return salary; }
        public void setSalary(double salary) { this.salary = salary; }
    }
    
    @Entity
    @Table(name = "invoices")
    public class bad_case_7 {
        @Id
        @GeneratedValue
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private int invoiceId; // Using int (32-bit) with default generation strategy
        
        private String invoiceNumber;
        private double amount;
        
        // Getters and setters
        public int getInvoiceId() { return invoiceId; }
        public void setInvoiceId(int invoiceId) { this.invoiceId = invoiceId; }
        public String getInvoiceNumber() { return invoiceNumber; }
        public void setInvoiceNumber(String invoiceNumber) { this.invoiceNumber = invoiceNumber; }
        public double getAmount() { return amount; }
        public void setAmount(double amount) { this.amount = amount; }
    }
    
    @Entity
    @Table(name = "transactions")
    public class bad_case_8 {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        @Column(name = "transaction_id", nullable = false, updatable = false)
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private Integer transactionId; // Using Integer (32-bit) with additional column constraints
        
        private String transactionType;
        private double amount;
        
        // Getters and setters
        public Integer getTransactionId() { return transactionId; }
        public void setTransactionId(Integer transactionId) { this.transactionId = transactionId; }
        public String getTransactionType() { return transactionType; }
        public void setTransactionType(String transactionType) { this.transactionType = transactionType; }
        public double getAmount() { return amount; }
        public void setAmount(double amount) { this.amount = amount; }
    }
    
    @Entity
    @Table(name = "articles")
    public class bad_case_9 {
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private int id; // Using int (32-bit) for auto-incremented ID
        
        @Version
        private int version;
        private String title;
        private String content;
        
        // Getters and setters
        public int getId() { return id; }
        public void setId(int id) { this.id = id; }
        public int getVersion() { return version; }
        public void setVersion(int version) { this.version = version; }
        public String getTitle() { return title; }
        public void setTitle(String title) { this.title = title; }
        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }
    }
    
    @Entity
    @Table(name = "comments")
    public class bad_case_10 {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private Integer commentId; // Using Integer (32-bit) for auto-incremented ID
        
        private String commentText;
        private int articleId;
        
        // Getters and setters
        public Integer getCommentId() { return commentId; }
        public void setCommentId(Integer commentId) { this.commentId = commentId; }
        public String getCommentText() { return commentText; }
        public void setCommentText(String commentText) { this.commentText = commentText; }
        public int getArticleId() { return articleId; }
        public void setArticleId(int articleId) { this.articleId = articleId; }
    }
    
    @Entity
    @Table(name = "categories")
    public class bad_case_11 {
        @Id
        @GeneratedValue(strategy = GenerationType.SEQUENCE)
        @SequenceGenerator(name = "category_seq", sequenceName = "category_sequence", initialValue = 1000)
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private int categoryId; // Using int (32-bit) with sequence starting at 1000
        
        private String categoryName;
        private String description;
        
        // Getters and setters
        public int getCategoryId() { return categoryId; }
        public void setCategoryId(int categoryId) { this.categoryId = categoryId; }
        public String getCategoryName() { return categoryName; }
        public void setCategoryName(String categoryName) { this.categoryName = categoryName; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
    }
    
    @Entity
    @Table(name = "tags")
    public class bad_case_12 {
        @Id
        @GeneratedValue(strategy = GenerationType.TABLE)
        @TableGenerator(name = "tag_gen", table = "id_generator", pkColumnName = "gen_key", 
                       valueColumnName = "gen_value", pkColumnValue = "tag_id", initialValue = 1)
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private Integer tagId; // Using Integer (32-bit) with detailed table generator
        
        private String tagName;
        
        // Getters and setters
        public Integer getTagId() { return tagId; }
        public void setTagId(Integer tagId) { this.tagId = tagId; }
        public String getTagName() { return tagName; }
        public void setTagName(String tagName) { this.tagName = tagName; }
    }
    
    @Entity
    @Table(name = "events")
    public class bad_case_13 {
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        @Column(name = "event_id")
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private int eventId; // Using int (32-bit) for auto-incremented ID
        
        private String eventName;
        private String location;
        private java.util.Date eventDate;
        
        // Getters and setters
        public int getEventId() { return eventId; }
        public void setEventId(int eventId) { this.eventId = eventId; }
        public String getEventName() { return eventName; }
        public void setEventName(String eventName) { this.eventName = eventName; }
        public String getLocation() { return location; }
        public void setLocation(String location) { this.location = location; }
        public java.util.Date getEventDate() { return eventDate; }
        public void setEventDate(java.util.Date eventDate) { this.eventDate = eventDate; }
    }
    
    @Entity
    @Table(name = "tickets")
    public class bad_case_14 {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private Integer ticketId; // Using Integer (32-bit) for auto-incremented ID
        
        private String ticketCode;
        private double price;
        private int eventId;
        
        // Getters and setters
        public Integer getTicketId() { return ticketId; }
        public void setTicketId(Integer ticketId) { this.ticketId = ticketId; }
        public String getTicketCode() { return ticketCode; }
        public void setTicketCode(String ticketCode) { this.ticketCode = ticketCode; }
        public double getPrice() { return price; }
        public void setPrice(double price) { this.price = price; }
        public int getEventId() { return eventId; }
        public void setEventId(int eventId) { this.eventId = eventId; }
    }
    
    @Entity
    @Table(name = "logs")
    public class bad_case_15 {
        @Id
        @GeneratedValue(strategy = GenerationType.SEQUENCE)
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        private int logId; // Using int (32-bit) for auto-incremented ID
        
        private String logMessage;
        private String logLevel;
        private java.util.Date timestamp;
        
        // Getters and setters
        public int getLogId() { return logId; }
        public void setLogId(int logId) { this.logId = logId; }
        public String getLogMessage() { return logMessage; }
        public void setLogMessage(String logMessage) { this.logMessage = logMessage; }
        public String getLogLevel() { return logLevel; }
        public void setLogLevel(String logLevel) { this.logLevel = logLevel; }
        public java.util.Date getTimestamp() { return timestamp; }
        public void setTimestamp(java.util.Date timestamp) { this.timestamp = timestamp; }
    }
    
    // True Negatives (Safe Code)
    
    @Entity
    public class good_case_1 {
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private long id; // Using long (64-bit) for auto-incremented ID
        
        private String name;
        
        // Getters and setters
        public long getId() { return id; }
        public void setId(long id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }
    
    @Entity
    public class good_case_2 {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private Long userId; // Using Long (64-bit) for auto-incremented ID
        
        private String email;
        
        // Getters and setters
        public Long getUserId() { return userId; }
        public void setUserId(Long userId) { this.userId = userId; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }
    
    @Entity
    @Table(name = "products")
    public class good_case_3 {
        @Id
        @GeneratedValue(strategy = GenerationType.SEQUENCE)
        @Column(name = "product_id")
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private long productId; // Using long (64-bit) for auto-incremented ID with sequence strategy
        
        private String productName;
        private double price;
        
        // Getters and setters
        public long getProductId() { return productId; }
        public void setProductId(long productId) { this.productId = productId; }
        public String getProductName() { return productName; }
        public void setProductName(String productName) { this.productName = productName; }
        public double getPrice() { return price; }
        public void setPrice(double price) { this.price = price; }
    }
    
    @Entity
    @Table(name = "orders")
    public class good_case_4 {
        @Id
        @GeneratedValue(strategy = GenerationType.TABLE)
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private Long orderId; // Using Long (64-bit) for auto-incremented ID with table strategy
        
        private String customerName;
        private double totalAmount;
        
        // Getters and setters
        public Long getOrderId() { return orderId; }
        public void setOrderId(Long orderId) { this.orderId = orderId; }
        public String getCustomerName() { return customerName; }
        public void setCustomerName(String customerName) { this.customerName = customerName; }
        public double getTotalAmount() { return totalAmount; }
        public void setTotalAmount(double totalAmount) { this.totalAmount = totalAmount; }
    }
    
    @Entity
    @Table(name = "customers")
    public class good_case_5 {
        @Id
        @SequenceGenerator(name = "customer_seq", sequenceName = "customer_sequence", allocationSize = 1)
        @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "customer_seq")
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private long customerId; // Using long (64-bit) with custom sequence generator
        
        private String firstName;
        private String lastName;
        
        // Getters and setters
        public long getCustomerId() { return customerId; }
        public void setCustomerId(long customerId) { this.customerId = customerId; }
        public String getFirstName() { return firstName; }
        public void setFirstName(String firstName) { this.firstName = firstName; }
        public String getLastName() { return lastName; }
        public void setLastName(String lastName) { this.lastName = lastName; }
    }
    
    @Entity
    @Table(name = "employees")
    public class good_case_6 {
        @Id
        @TableGenerator(name = "emp_gen", table = "id_gen", pkColumnName = "gen_name", 
                       valueColumnName = "gen_val", allocationSize = 100)
        @GeneratedValue(strategy = GenerationType.TABLE, generator = "emp_gen")
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private Long employeeId; // Using Long (64-bit) with custom table generator
        
        private String department;
        private double salary;
        
        // Getters and setters
        public Long getEmployeeId() { return employeeId; }
        public void setEmployeeId(Long employeeId) { this.employeeId = employeeId; }
        public String getDepartment() { return department; }
        public void setDepartment(String department) { this.department = department; }
        public double getSalary() { return salary; }
        public void setSalary(double salary) { this.salary = salary; }
    }
    
    @Entity
    @Table(name = "invoices")
    public class good_case_7 {
        @Id
        @GeneratedValue
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private long invoiceId; // Using long (64-bit) with default generation strategy
        
        private String invoiceNumber;
        private double amount;
        
        // Getters and setters
        public long getInvoiceId() { return invoiceId; }
        public void setInvoiceId(long invoiceId) { this.invoiceId = invoiceId; }
        public String getInvoiceNumber() { return invoiceNumber; }
        public void setInvoiceNumber(String invoiceNumber) { this.invoiceNumber = invoiceNumber; }
        public double getAmount() { return amount; }
        public void setAmount(double amount) { this.amount = amount; }
    }
    
    @Entity
    @Table(name = "transactions")
    public class good_case_8 {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        @Column(name = "transaction_id", nullable = false, updatable = false)
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private Long transactionId; // Using Long (64-bit) with additional column constraints
        
        private String transactionType;
        private double amount;
        
        // Getters and setters
        public Long getTransactionId() { return transactionId; }
        public void setTransactionId(Long transactionId) { this.transactionId = transactionId; }
        public String getTransactionType() { return transactionType; }
        public void setTransactionType(String transactionType) { this.transactionType = transactionType; }
        public double getAmount() { return amount; }
        public void setAmount(double amount) { this.amount = amount; }
    }
    
    @Entity
    @Table(name = "articles")
    public class good_case_9 {
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private long id; // Using long (64-bit) for auto-incremented ID
        
        @Version
        private int version; // Version field can be 32-bit as it's not the ID
        private String title;
        private String content;
        
        // Getters and setters
        public long getId() { return id; }
        public void setId(long id) { this.id = id; }
        public int getVersion() { return version; }
        public void setVersion(int version) { this.version = version; }
        public String getTitle() { return title; }
        public void setTitle(String title) { this.title = title; }
        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }
    }
    
    @Entity
    @Table(name = "comments")
    public class good_case_10 {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private Long commentId; // Using Long (64-bit) for auto-incremented ID
        
        private String commentText;
        private long articleId; // Using long for foreign key reference
        
        // Getters and setters
        public Long getCommentId() { return commentId; }
        public void setCommentId(Long commentId) { this.commentId = commentId; }
        public String getCommentText() { return commentText; }
        public void setCommentText(String commentText) { this.commentText = commentText; }
        public long getArticleId() { return articleId; }
        public void setArticleId(long articleId) { this.articleId = articleId; }
    }
    
    @Entity
    @Table(name = "categories")
    public class good_case_11 {
        @Id
        @GeneratedValue(strategy = GenerationType.SEQUENCE)
        @SequenceGenerator(name = "category_seq", sequenceName = "category_sequence", initialValue = 1000)
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private long categoryId; // Using long (64-bit) with sequence starting at 1000
        
        private String categoryName;
        private String description;
        
        // Getters and setters
        public long getCategoryId() { return categoryId; }
        public void setCategoryId(long categoryId) { this.categoryId = categoryId; }
        public String getCategoryName() { return categoryName; }
        public void setCategoryName(String categoryName) { this.categoryName = categoryName; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
    }
    
    @Entity
    @Table(name = "tags")
    public class good_case_12 {
        @Id
        @GeneratedValue(strategy = GenerationType.TABLE)
        @TableGenerator(name = "tag_gen", table = "id_generator", pkColumnName = "gen_key", 
                       valueColumnName = "gen_value", pkColumnValue = "tag_id", initialValue = 1)
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private Long tagId; // Using Long (64-bit) with detailed table generator
        
        private String tagName;
        
        // Getters and setters
        public Long getTagId() { return tagId; }
        public void setTagId(Long tagId) { this.tagId = tagId; }
        public String getTagName() { return tagName; }
        public void setTagName(String tagName) { this.tagName = tagName; }
    }
    
    @Entity
    @Table(name = "events")
    public class good_case_13 {
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        @Column(name = "event_id")
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private long eventId; // Using long (64-bit) for auto-incremented ID
        
        private String eventName;
        private String location;
        private java.util.Date eventDate;
        
        // Getters and setters
        public long getEventId() { return eventId; }
        public void setEventId(long eventId) { this.eventId = eventId; }
        public String getEventName() { return eventName; }
        public void setEventName(String eventName) { this.eventName = eventName; }
        public String getLocation() { return location; }
        public void setLocation(String location) { this.location = location; }
        public java.util.Date getEventDate() { return eventDate; }
        public void setEventDate(java.util.Date eventDate) { this.eventDate = eventDate; }
    }
    
    @Entity
    @Table(name = "tickets")
    public class good_case_14 {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private Long ticketId; // Using Long (64-bit) for auto-incremented ID
        
        private String ticketCode;
        private double price;
        private long eventId; // Using long for foreign key reference
        
        // Getters and setters
        public Long getTicketId() { return ticketId; }
        public void setTicketId(Long ticketId) { this.ticketId = ticketId; }
        public String getTicketCode() { return ticketCode; }
        public void setTicketCode(String ticketCode) { this.ticketCode = ticketCode; }
        public double getPrice() { return price; }
        public void setPrice(double price) { this.price = price; }
        public long getEventId() { return eventId; }
        public void setEventId(long eventId) { this.eventId = eventId; }
    }
    
    @Entity
    @Table(name = "logs")
    public class good_case_15 {
        @Id
        @GeneratedValue(strategy = GenerationType.SEQUENCE)
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        private Long logId; // Using Long (64-bit) for auto-incremented ID
        
        private String logMessage;
        private String logLevel;
        private java.util.Date timestamp;
        
        // Getters and setters
        public Long getLogId() { return logId; }
        public void setLogId(Long logId) { this.logId = logId; }
        public String getLogMessage() { return logMessage; }
        public void setLogMessage(String logMessage) { this.logMessage = logMessage; }
        public String getLogLevel() { return logLevel; }
        public void setLogLevel(String logLevel) { this.logLevel = logLevel; }
        public java.util.Date getTimestamp() { return timestamp; }
        public void setTimestamp(java.util.Date timestamp) { this.timestamp = timestamp; }
    }
}