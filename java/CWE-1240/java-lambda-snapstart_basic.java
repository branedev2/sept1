import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Calendar;
import java.util.UUID;
import java.security.SecureRandom;
import java.util.Random;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import org.springframework.stereotype.Component;
import javax.annotation.PostConstruct;

// True Positive Examples (Vulnerable Code)

class BadCase1 {
    private Date timestamp;
    
    public BadCase1() {
        // ruleid: java-lambda-snapstart
        this.timestamp = new Date(); // Timestamp in constructor will be frozen at snapshot time
    }
    
    public Date getTimestamp() {
        return timestamp;
    }
}

class BadCase2 {
    private long currentTimeMillis;
    
    public BadCase2() {
        // ruleid: java-lambda-snapstart
        this.currentTimeMillis = System.currentTimeMillis(); // Time value in constructor
    }
    
    public long getTime() {
        return currentTimeMillis;
    }
}

class BadCase3 {
    private Instant creationTime;
    
    public BadCase3() {
        // ruleid: java-lambda-snapstart
        this.creationTime = Instant.now(); // Using Instant.now() in constructor
    }
    
    public Instant getCreationTime() {
        return creationTime;
    }
}

class BadCase4 {
    private LocalDateTime startTime;
    
    public BadCase4() {
        // ruleid: java-lambda-snapstart
        this.startTime = LocalDateTime.now(); // Using LocalDateTime.now() in constructor
    }
    
    public LocalDateTime getStartTime() {
        return startTime;
    }
}

class BadCase5 {
    private Calendar calendar;
    
    public BadCase5() {
        // ruleid: java-lambda-snapstart
        this.calendar = Calendar.getInstance(); // Calendar instance in constructor
    }
    
    public Calendar getCalendar() {
        return calendar;
    }
}

class BadCase6 {
    private UUID randomId;
    
    public BadCase6() {
        // ruleid: java-lambda-snapstart
        this.randomId = UUID.randomUUID(); // Random UUID in constructor
    }
    
    public UUID getId() {
        return randomId;
    }
}

class BadCase7 {
    private SecureRandom secureRandom;
    
    public BadCase7() {
        // ruleid: java-lambda-snapstart
        this.secureRandom = new SecureRandom(); // SecureRandom in constructor
        secureRandom.setSeed(System.currentTimeMillis()); // Seeding with time
    }
    
    public int getRandomValue() {
        return secureRandom.nextInt();
    }
}

class BadCase8 {
    private Random random;
    private long seed;
    
    public BadCase8() {
        // ruleid: java-lambda-snapstart
        this.seed = System.nanoTime(); // Using nanoTime in constructor
        this.random = new Random(seed);
    }
    
    public int getRandomNumber() {
        return random.nextInt(100);
    }
}

class BadCase9 {
    private SecretKey secretKey;
    
    public BadCase9() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            // ruleid: java-lambda-snapstart
            keyGen.init(256, new SecureRandom()); // SecureRandom initialized in constructor
            this.secretKey = keyGen.generateKey(); // Key generation in constructor
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    public SecretKey getSecretKey() {
        return secretKey;
    }
}

class BadCase10 {
    private String sessionId;
    
    public BadCase10() {
        // ruleid: java-lambda-snapstart
        this.sessionId = generateSessionId(); // Generating session ID in constructor
    }
    
    private String generateSessionId() {
        return Long.toHexString(System.currentTimeMillis());
    }
    
    public String getSessionId() {
        return sessionId;
    }
}

class BadCase11 {
    private long expirationTime;
    
    public BadCase11() {
        // ruleid: java-lambda-snapstart
        this.expirationTime = System.currentTimeMillis() + 3600000; // Setting expiration time in constructor
    }
    
    public boolean isExpired() {
        return System.currentTimeMillis() > expirationTime;
    }
}

class BadCase12 {
    private String token;
    private long createdAt;
    
    public BadCase12() {
        // ruleid: java-lambda-snapstart
        this.createdAt = Instant.now().getEpochSecond(); // Using Instant for timestamp in constructor
        this.token = "TOKEN-" + createdAt;
    }
    
    public String getToken() {
        return token;
    }
}

class BadCase13 {
    private byte[] nonce;
    
    public BadCase13() {
        // ruleid: java-lambda-snapstart
        this.nonce = generateNonce(); // Generating nonce in constructor
    }
    
    private byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);
        return nonce;
    }
    
    public byte[] getNonce() {
        return nonce;
    }
}

@Component
class BadCase14 {
    private long initTime;
    
    @PostConstruct
    public void init() {
        // ruleid: java-lambda-snapstart
        this.initTime = System.currentTimeMillis(); // Using time in @PostConstruct which is similar to constructor
    }
    
    public long getInitTime() {
        return initTime;
    }
}

class BadCase15 {
    private String uniqueId;
    private long timestamp;
    
    public BadCase15(String id) {
        this.uniqueId = id;
        // ruleid: java-lambda-snapstart
        this.timestamp = System.currentTimeMillis(); // Setting timestamp in constructor with parameters
    }
    
    public String getUniqueId() {
        return uniqueId + "-" + timestamp;
    }
}

// True Negative Examples (Safe Code)

class GoodCase1 {
    private Date timestamp;
    
    public GoodCase1() {
        // Constructor without timestamp
    }
    
    // ok: java-lambda-snapstart
    public Date getTimestamp() {
        return new Date(); // Getting current time when method is called
    }
}

class GoodCase2 {
    // ok: java-lambda-snapstart
    public long getCurrentTimeMillis() {
        return System.currentTimeMillis(); // Getting time when method is called
    }
}

class GoodCase3 {
    // ok: java-lambda-snapstart
    public Instant getNow() {
        return Instant.now(); // Getting current instant when method is called
    }
}

class GoodCase4 {
    private String id;
    
    public GoodCase4(String id) {
        this.id = id; // No timestamp in constructor
    }
    
    // ok: java-lambda-snapstart
    public LocalDateTime getCurrentTime() {
        return LocalDateTime.now(); // Getting current time when method is called
    }
}

class GoodCase5 implements com.amazonaws.services.lambda.runtime.RequestHandler<Object, String> {
    private String configValue;
    
    public GoodCase5() {
        this.configValue = "static-config"; // Static value, not time-dependent
    }
    
    // ok: java-lambda-snapstart
    @Override
    public String handleRequest(Object input, Context context) {
        long requestTime = System.currentTimeMillis(); // Time captured during request handling
        return "Request processed at: " + requestTime;
    }
}

class GoodCase6 {
    private UUID staticId;
    
    public GoodCase6() {
        this.staticId = UUID.fromString("38400000-8cf0-11bd-b23e-10b96e4ef00d"); // Static UUID
    }
    
    // ok: java-lambda-snapstart
    public UUID generateDynamicId() {
        return UUID.randomUUID(); // Generate UUID when method is called
    }
}

class GoodCase7 {
    // ok: java-lambda-snapstart
    public SecureRandom getSecureRandom() {
        SecureRandom random = new SecureRandom();
        random.setSeed(System.currentTimeMillis()); // Seeding with current time when method is called
        return random;
    }
}

class GoodCase8 {
    // ok: java-lambda-snapstart
    public void afterRestore() {
        // This is called after Lambda SnapStart restore
        Date currentTime = new Date(); // Safe to use time here
        System.out.println("Restored at: " + currentTime);
    }
}

class GoodCase9 {
    private static final String STATIC_KEY = "static-key-value"; // Static value
    
    public GoodCase9() {
        // No time-dependent operations
    }
    
    // ok: java-lambda-snapstart
    public SecretKey generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256, new SecureRandom()); // SecureRandom initialized when method is called
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}

class GoodCase10 {
    // ok: java-lambda-snapstart
    public String generateSessionId() {
        return Long.toHexString(System.currentTimeMillis()); // Generate session ID when method is called
    }
}

class GoodCase11 {
    private long fixedDuration = 3600000; // 1 hour in milliseconds
    
    // ok: java-lambda-snapstart
    public long calculateExpirationTime() {
        return System.currentTimeMillis() + fixedDuration; // Calculate expiration when method is called
    }
}

class GoodCase12 {
    // ok: java-lambda-snapstart
    public String createToken() {
        long timestamp = Instant.now().getEpochSecond();
        return "TOKEN-" + timestamp; // Create token with current time when method is called
    }
}

class GoodCase13 {
    // ok: java-lambda-snapstart
    public byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);
        return nonce; // Generate nonce when method is called
    }
}

class GoodCase14 {
    private long initTime;
    
    // ok: java-lambda-snapstart
    public void afterRestore(Context context) {
        LambdaLogger logger = context.getLogger();
        this.initTime = System.currentTimeMillis(); // Setting time in afterRestore method
        logger.log("Restored at: " + initTime);
    }
}

class GoodCase15 {
    private String uniqueId;
    
    public GoodCase15(String id) {
        this.uniqueId = id; // Only setting static data in constructor
    }
    
    // ok: java-lambda-snapstart
    public String getUniqueIdWithTimestamp() {
        return uniqueId + "-" + System.currentTimeMillis(); // Adding timestamp when method is called
    }
}