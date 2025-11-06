import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Calendar;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.Random;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.ZonedDateTime;
import java.time.OffsetDateTime;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.joda.time.DateTime;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import org.springframework.stereotype.Component;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.google.cloud.Timestamp as GcpTimestamp;
import io.quarkus.runtime.StartupEvent;
import javax.enterprise.event.Observes;
import javax.inject.Singleton;
import io.micronaut.runtime.event.annotation.EventListener;
import io.micronaut.context.event.StartupEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Security Issue: Lambda SnapStart can cause timestamp inconsistencies when timestamps are assigned in constructors

// True Positive Examples (Vulnerable/Insecure Code)

class bad_case_1 {
    private final Date creationTime;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_1() {
        // ruleid: java-lambda-snapstart
        this.creationTime = new Date();
    }
    
    public Date getCreationTime() {
        return creationTime;
    }
}
// {/fact}

class bad_case_2 {
    private final long timestamp;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_2() {
        // ruleid: java-lambda-snapstart
        this.timestamp = System.currentTimeMillis();
    }
    
    public long getTimestamp() {
        return timestamp;
    }
}
// {/fact}

class bad_case_3 {
    private final Instant instant;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_3() {
        // ruleid: java-lambda-snapstart
        this.instant = Instant.now();
    }
    
    public Instant getInstant() {
        return instant;
    }
}
// {/fact}

class bad_case_4 {
    private final LocalDateTime localDateTime;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_4() {
        // ruleid: java-lambda-snapstart
        this.localDateTime = LocalDateTime.now();
    }
    
    public LocalDateTime getLocalDateTime() {
        return localDateTime;
    }
}
// {/fact}

class bad_case_5 {
    private final Calendar calendar;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_5() {
        // ruleid: java-lambda-snapstart
        this.calendar = Calendar.getInstance();
    }
    
    public Calendar getCalendar() {
        return calendar;
    }
}
// {/fact}

class bad_case_6 {
    private final Timestamp sqlTimestamp;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_6() {
        // ruleid: java-lambda-snapstart
        this.sqlTimestamp = new Timestamp(System.currentTimeMillis());
    }
    
    public Timestamp getSqlTimestamp() {
        return sqlTimestamp;
    }
}
// {/fact}

class bad_case_7 {
    private final ZonedDateTime zonedDateTime;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_7() {
        // ruleid: java-lambda-snapstart
        this.zonedDateTime = ZonedDateTime.now();
    }
    
    public ZonedDateTime getZonedDateTime() {
        return zonedDateTime;
    }
}
// {/fact}

class bad_case_8 {
    private final OffsetDateTime offsetDateTime;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_8() {
        // ruleid: java-lambda-snapstart
        this.offsetDateTime = OffsetDateTime.now();
    }
    
    public OffsetDateTime getOffsetDateTime() {
        return offsetDateTime;
    }
}
// {/fact}

class bad_case_9 {
    private final DateTime jodaDateTime;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_9() {
        // ruleid: java-lambda-snapstart
        this.jodaDateTime = DateTime.now();
    }
    
    public DateTime getJodaDateTime() {
        return jodaDateTime;
    }
}
// {/fact}

class bad_case_10 {
    private final long nanoTime;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_10() {
        // ruleid: java-lambda-snapstart
        this.nanoTime = System.nanoTime();
    }
    
    public long getNanoTime() {
        return nanoTime;
    }
}
// {/fact}

class bad_case_11 {
    private final GcpTimestamp gcpTimestamp;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_11() {
        // ruleid: java-lambda-snapstart
        this.gcpTimestamp = GcpTimestamp.now();
    }
    
    public GcpTimestamp getGcpTimestamp() {
        return gcpTimestamp;
    }
}
// {/fact}

@Component
class bad_case_12 {
    private final Logger logger = LoggerFactory.getLogger(bad_case_12.class);
    private final Instant startupTime;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_12() {
        // ruleid: java-lambda-snapstart
        this.startupTime = Instant.now();
        logger.info("Service started at: {}", startupTime);
    }
}
// {/fact}

@Singleton
class bad_case_13 {
    private final long initializationTimestamp;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_13() {
        // ruleid: java-lambda-snapstart
        this.initializationTimestamp = System.currentTimeMillis();
    }
    
    public void onStart(@Observes StartupEvent ev) {
        System.out.println("Application started at: " + initializationTimestamp);
    }
}
// {/fact}

class bad_case_14 {
    private final Clock clock;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_14() {
        // ruleid: java-lambda-snapstart
        this.clock = Clock.systemUTC();
    }
    
    public Instant getCurrentTime() {
        return clock.instant();
    }
}
// {/fact}

class bad_case_15 {
    private final String timeBasedId;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public bad_case_15() {
        // ruleid: java-lambda-snapstart
        this.timeBasedId = "TX-" + System.currentTimeMillis();
    }
    
    public String getTimeBasedId() {
        return timeBasedId;
    }
}
// {/fact}

// True Negative Examples (Safe/Secure Code)

class good_case_1 {
    private Date creationTime;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_1() {
        // Constructor without timestamp initialization
    }
    
    // ok: java-lambda-snapstart
    public void afterRestore() {
        this.creationTime = new Date();
    }
    
    public Date getCreationTime() {
        return creationTime;
    }
}
// {/fact}

class good_case_2 implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private long timestamp;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_2() {
        // Constructor without timestamp initialization
    }
    
    @Override
    // ok: java-lambda-snapstart
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        this.timestamp = System.currentTimeMillis();
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(200)
                .withBody("Current time: " + timestamp);
    }
}
// {/fact}

class good_case_3 {
    private Instant instant;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_3() {
        // Constructor without timestamp initialization
    }
    
    // ok: java-lambda-snapstart
    public void processRequest() {
        this.instant = Instant.now();
    }
    
    public Instant getInstant() {
        return instant;
    }
}
// {/fact}

class good_case_4 {
    // Using final but not initializing in constructor
    private final LocalDateTime localDateTime;
    
    // ok: java-lambda-snapstart
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_4(LocalDateTime providedTime) {
        this.localDateTime = providedTime;
    }
    
    public LocalDateTime getLocalDateTime() {
        return localDateTime;
    }
    
    // Factory method to create instance with current time
    public static good_case_4 createWithCurrentTime() {
        return new good_case_4(LocalDateTime.now());
    }
}
// {/fact}

class good_case_5 {
    private Calendar calendar;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_5() {
        // Constructor without timestamp initialization
    }
    
    // ok: java-lambda-snapstart
    public void initializeCalendar() {
        this.calendar = Calendar.getInstance();
    }
    
    public Calendar getCalendar() {
        return calendar;
    }
}
// {/fact}

class good_case_6 {
    private Timestamp sqlTimestamp;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_6() {
        // Constructor without timestamp initialization
    }
    
    // ok: java-lambda-snapstart
    public void setTimestamp() {
        this.sqlTimestamp = new Timestamp(System.currentTimeMillis());
    }
    
    public Timestamp getSqlTimestamp() {
        return sqlTimestamp;
    }
}
// {/fact}

class good_case_7 {
    private ZonedDateTime zonedDateTime;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_7() {
        // Constructor without timestamp initialization
    }
    
    // Lambda runtime hook
    // ok: java-lambda-snapstart
    public void afterRestore() {
        this.zonedDateTime = ZonedDateTime.now();
    }
    
    public ZonedDateTime getZonedDateTime() {
        return zonedDateTime;
    }
}
// {/fact}

class good_case_8 {
    // Using a supplier instead of direct initialization
    private final Supplier<OffsetDateTime> timeSupplier;
    
    // ok: java-lambda-snapstart
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_8() {
        this.timeSupplier = OffsetDateTime::now;
    }
    
    public OffsetDateTime getCurrentTime() {
        return timeSupplier.get();
    }
}
// {/fact}

class good_case_9 {
    private DateTime jodaDateTime;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_9() {
        // Constructor without timestamp initialization
    }
    
    // ok: java-lambda-snapstart
    @EventListener
    public void onStartup(StartupEvent event) {
        this.jodaDateTime = DateTime.now();
    }
    
    public DateTime getJodaDateTime() {
        return jodaDateTime;
    }
}
// {/fact}

class good_case_10 {
    // Using a non-time-based ID
    private final String id;
    
    // ok: java-lambda-snapstart
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_10() {
        this.id = UUID.randomUUID().toString();
    }
    
    public String getId() {
        return id;
    }
}
// {/fact}

class good_case_11 {
    private GcpTimestamp gcpTimestamp;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_11() {
        // Constructor without timestamp initialization
    }
    
    // ok: java-lambda-snapstart
    public void initializeTimestamp() {
        this.gcpTimestamp = GcpTimestamp.now();
    }
    
    public GcpTimestamp getGcpTimestamp() {
        return gcpTimestamp;
    }
}
// {/fact}

@Component
class good_case_12 {
    private final Logger logger = LoggerFactory.getLogger(good_case_12.class);
    private Instant startupTime;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_12() {
        // Constructor without timestamp initialization
    }
    
    // ok: java-lambda-snapstart
    @Bean
    public void initializeStartupTime() {
        this.startupTime = Instant.now();
        logger.info("Service started at: {}", startupTime);
    }
}
// {/fact}

@Singleton
class good_case_13 {
    private long initializationTimestamp;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_13() {
        // Constructor without timestamp initialization
    }
    
    // ok: java-lambda-snapstart
    public void onStart(@Observes StartupEvent ev) {
        this.initializationTimestamp = System.currentTimeMillis();
        System.out.println("Application started at: " + initializationTimestamp);
    }
}
// {/fact}

class good_case_14 {
    private Clock clock;
    
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_14() {
        // Constructor without timestamp initialization
    }
    
    // ok: java-lambda-snapstart
    public void initializeClock() {
        this.clock = Clock.systemUTC();
    }
    
    public Instant getCurrentTime() {
        return clock.instant();
    }
}
// {/fact}

class good_case_15 {
    // Using a constant value instead of time-based ID
    private final String transactionPrefix;
    private int counter;
    
    // ok: java-lambda-snapstart
// {fact rule=cryptographic-key-generator@v1.0 defects=0}
    public good_case_15() {
        this.transactionPrefix = "TX-";
        this.counter = 0;
    }
    
    public String generateTimeBasedId() {
        return transactionPrefix + System.currentTimeMillis() + "-" + (++counter);
    }
}
// {/fact}