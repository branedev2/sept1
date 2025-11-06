import javax.persistence.*;
import jakarta.persistence.*;
import org.hibernate.annotations.*;
import java.math.BigInteger;
import java.util.UUID;
import org.springframework.data.annotation.Id as SpringId;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.cassandra.core.mapping.PrimaryKey;
import org.springframework.data.couchbase.core.mapping.id.GeneratedValue;
import org.springframework.data.couchbase.core.mapping.Document as CouchbaseDocument;
import org.springframework.data.elasticsearch.annotations.Document as ElasticsearchDocument;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.redis.core.RedisHash;
import com.datastax.oss.driver.api.mapper.annotations.Entity as CassandraEntity;
import com.datastax.oss.driver.api.mapper.annotations.PartitionKey;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import org.bson.Document;
import org.bson.types.ObjectId;
import io.quarkus.hibernate.orm.panache.PanacheEntity;
import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import io.micronaut.data.annotation.GeneratedValue as MicronautGeneratedValue;
import io.micronaut.data.annotation.Id as MicronautId;
import io.micronaut.data.annotation.MappedEntity;
import org.eclipse.microprofile.graphql.Id as GraphQLId;
import org.eclipse.microprofile.graphql.Type;

// Security Issue: Using 32-bit data types for auto-incremented IDs can cause issues when tables grow beyond 2^32 entries

// True Positive Examples (Vulnerable/Insecure Code)

public class BadCase1 {
    @Entity
    public class User {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        private int userId;
        
        private String username;
        private String email;
        
        // Getters and setters
    }
}

public class BadCase2 {
    @Entity
    @Table(name = "customers")
    public class Customer {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Integer customerId;
        
        private String name;
        private String address;
        
        // Getters and setters
    }
}

public class BadCase3 {
    @Entity
    @Table(name = "products")
    public class Product {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @jakarta.persistence.Id
        @jakarta.persistence.GeneratedValue
        private int productId;
        
        private String name;
        private double price;
        
        // Getters and setters
    }
}

public class BadCase4 {
    @MappedSuperclass
    public abstract class BaseEntity {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @GeneratedValue(strategy = GenerationType.SEQUENCE)
        protected Integer id;
        
        // Getters and setters
    }
    
    @Entity
    public class Order extends BaseEntity {
        private String orderNumber;
        private double totalAmount;
        
        // Getters and setters
    }
}

public class BadCase5 {
    @Entity
    public class Employee {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @GeneratedValue(generator = "increment")
        @GenericGenerator(name = "increment", strategy = "increment")
        private int employeeId;
        
        private String firstName;
        private String lastName;
        
        // Getters and setters
    }
}

public class BadCase6 {
    @MappedEntity
    public class Invoice {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @MicronautId
        @MicronautGeneratedValue
        private Integer invoiceId;
        
        private String invoiceNumber;
        private double amount;
        
        // Getters and setters
    }
}

public class BadCase7 {
    @Entity
    public class Department extends PanacheEntityBase {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @GeneratedValue
        public int id;
        
        public String name;
        public String location;
        
        // Getters and setters
    }
}

public class BadCase8 {
    @Document
    public class Article {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @SpringId
        @org.springframework.data.mongodb.core.mapping.Field("_id")
        private int articleId;
        
        private String title;
        private String content;
        
        // Getters and setters
    }
}

public class BadCase9 {
    @CassandraEntity
    public class Sensor {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @PartitionKey
        private int sensorId;
        
        private String location;
        private double reading;
        
        // Getters and setters
    }
}

public class BadCase10 {
    @CouchbaseDocument
    public class Product {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @org.springframework.data.annotation.Id
        @GeneratedValue
        private Integer productId;
        
        private String name;
        private double price;
        
        // Getters and setters
    }
}

public class BadCase11 {
    @ElasticsearchDocument(indexName = "logs")
    public class LogEntry {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @org.springframework.data.annotation.Id
        private int logId;
        
        @Field(name = "message")
        private String message;
        
        private String severity;
        
        // Getters and setters
    }
}

public class BadCase12 {
    @RedisHash("sessions")
    public class Session {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @org.springframework.data.annotation.Id
        private int sessionId;
        
        private String username;
        private long timestamp;
        
        // Getters and setters
    }
}

public class BadCase13 {
    @Type
    public class GraphQLUser {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @GraphQLId
        private Integer id;
        
        private String name;
        private String email;
        
        // Getters and setters
    }
}

public class BadCase14 {
    @Entity
    @Table(name = "transactions")
    public class Transaction {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @SequenceGenerator(name = "transaction_seq", sequenceName = "transaction_seq")
        @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "transaction_seq")
        private int transactionId;
        
        private String description;
        private double amount;
        
        // Getters and setters
    }
}

public class BadCase15 {
    @Entity
    @Table(name = "audit_logs")
    public class AuditLog {
        // ruleid: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @TableGenerator(name = "audit_gen", table = "id_gen", pkColumnName = "gen_name", 
                       valueColumnName = "gen_val", pkColumnValue = "audit_id", initialValue = 1)
        @GeneratedValue(strategy = GenerationType.TABLE, generator = "audit_gen")
        private Integer id;
        
        private String action;
        private String username;
        
        // Getters and setters
    }
}

// True Negative Examples (Safe/Secure Code)

public class GoodCase1 {
    @Entity
    public class User {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @GeneratedValue(strategy = GenerationType.AUTO)
        private Long userId;
        
        private String username;
        private String email;
        
        // Getters and setters
    }
}

public class GoodCase2 {
    @Entity
    @Table(name = "customers")
    public class Customer {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private long customerId;
        
        private String name;
        private String address;
        
        // Getters and setters
    }
}

public class GoodCase3 {
    @Entity
    @Table(name = "products")
    public class Product {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @jakarta.persistence.Id
        @jakarta.persistence.GeneratedValue
        private Long productId;
        
        private String name;
        private double price;
        
        // Getters and setters
    }
}

public class GoodCase4 {
    @MappedSuperclass
    public abstract class BaseEntity {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @GeneratedValue(strategy = GenerationType.SEQUENCE)
        protected BigInteger id;
        
        // Getters and setters
    }
    
    @Entity
    public class Order extends BaseEntity {
        private String orderNumber;
        private double totalAmount;
        
        // Getters and setters
    }
}

public class GoodCase5 {
    @Entity
    public class Employee {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @GeneratedValue(generator = "UUID")
        @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
        private UUID employeeId;
        
        private String firstName;
        private String lastName;
        
        // Getters and setters
    }
}

public class GoodCase6 {
    @MappedEntity
    public class Invoice {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @MicronautId
        @MicronautGeneratedValue
        private Long invoiceId;
        
        private String invoiceNumber;
        private double amount;
        
        // Getters and setters
    }
}

public class GoodCase7 {
    @Entity
    public class Department extends PanacheEntityBase {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @GeneratedValue
        public Long id;
        
        public String name;
        public String location;
        
        // Getters and setters
    }
}

public class GoodCase8 {
    @Document
    public class Article {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @SpringId
        private String articleId;
        
        private String title;
        private String content;
        
        // Getters and setters
    }
}

public class GoodCase9 {
    @CassandraEntity
    public class Sensor {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @PartitionKey
        private UUID sensorId;
        
        private String location;
        private double reading;
        
        // Getters and setters
    }
}

public class GoodCase10 {
    @CouchbaseDocument
    public class Product {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @org.springframework.data.annotation.Id
        @GeneratedValue
        private String productId;
        
        private String name;
        private double price;
        
        // Getters and setters
    }
}

public class GoodCase11 {
    @ElasticsearchDocument(indexName = "logs")
    public class LogEntry {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @org.springframework.data.annotation.Id
        private String logId;
        
        @Field(name = "message")
        private String message;
        
        private String severity;
        
        // Getters and setters
    }
}

public class GoodCase12 {
    @RedisHash("sessions")
    public class Session {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @org.springframework.data.annotation.Id
        private String sessionId;
        
        private String username;
        private long timestamp;
        
        // Getters and setters
    }
}

public class GoodCase13 {
    @Type
    public class GraphQLUser {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @GraphQLId
        private String id;
        
        private String name;
        private String email;
        
        // Getters and setters
    }
}

public class GoodCase14 {
    @Entity
    @Table(name = "transactions")
    public class Transaction {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @SequenceGenerator(name = "transaction_seq", sequenceName = "transaction_seq")
        @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "transaction_seq")
        private Long transactionId;
        
        private String description;
        private double amount;
        
        // Getters and setters
    }
}

public class GoodCase15 {
    @Entity
    @Table(name = "audit_logs")
    public class AuditLog {
        // ok: java-javax-persistence-id-annotation-attached-to-32bit
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private BigInteger id;
        
        private String action;
        private String username;
        
        // Getters and setters
    }
}