import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

public class LoggingExamples {
    private static final Logger logger = LoggerFactory.getLogger(LoggingExamples.class);

    // True Positive Examples (Vulnerable/Inefficient Code)

// {fact rule=inefficient-cpu-computation@v1.0 defects=1}
    public void bad_case_1() {
        String username = "user123";
        int loginAttempts = 5;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.debug("User " + username + " has attempted to login " + loginAttempts + " times");
    }

    public void bad_case_2() {
        String ipAddress = "192.168.1.1";
        int port = 8080;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info(String.format("Connection from %s on port %d", ipAddress, port));
    }

    public void bad_case_3() {
        String filename = "config.xml";
        long fileSize = 1024;
        StringBuilder sb = new StringBuilder();
        sb.append("File ");
        sb.append(filename);
        sb.append(" has size ");
        sb.append(fileSize);
        sb.append(" bytes");
        // ruleid: java-avoid-string-formatting-in-logging
        logger.warn(sb.toString());
    }

    public void bad_case_4() {
        String userId = "admin";
        String action = "DELETE";
        String resource = "users/123";
        // ruleid: java-avoid-string-formatting-in-logging
        logger.error("User " + userId + " attempted " + action + " on resource " + resource);
    }

    public void bad_case_5() {
        int statusCode = 404;
        String path = "/api/users";
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info(String.format("HTTP %d response for path %s", statusCode, path));
    }

    public void bad_case_6() {
        String transactionId = UUID.randomUUID().toString();
        double amount = 199.99;
        StringBuilder logMessage = new StringBuilder();
        logMessage.append("Processing transaction ");
        logMessage.append(transactionId);
        logMessage.append(" for $");
        logMessage.append(amount);
        // ruleid: java-avoid-string-formatting-in-logging
        logger.debug(logMessage.toString());
    }

    public void bad_case_7() {
        int recordsProcessed = 1500;
        long processingTime = 3500;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info("Batch job completed: " + recordsProcessed + " records in " + processingTime + "ms");
    }

    public void bad_case_8() {
        String username = "jsmith";
        int permissionLevel = 3;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.debug(String.format("Checking authorization for user %s with permission level %d", username, permissionLevel));
    }

    public void bad_case_9() {
        String databaseName = "customers";
        int connectionPoolSize = 10;
        StringBuilder sb = new StringBuilder()
            .append("Database connection established to ")
            .append(databaseName)
            .append(" with pool size ")
            .append(connectionPoolSize);
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info(sb.toString());
    }

    public void bad_case_10() {
        String methodName = "processPayment";
        long executionTime = 250;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.debug("Method " + methodName + " executed in " + executionTime + "ms");
    }

    public void bad_case_11() {
        String serviceName = "AuthService";
        String errorCode = "AUTH_FAILED";
        Exception e = new RuntimeException("Authentication failed");
        // ruleid: java-avoid-string-formatting-in-logging
        logger.error(String.format("%s error: %s", serviceName, errorCode), e);
    }

    public void bad_case_12() {
        int activeUsers = 1250;
        int totalCapacity = 2000;
        StringBuilder message = new StringBuilder();
        message.append("System load: ");
        message.append(activeUsers);
        message.append("/");
        message.append(totalCapacity);
        message.append(" active users");
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info(message.toString());
    }

    public void bad_case_13() {
        String configFile = "app-config.json";
        boolean isValid = false;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.warn("Configuration file " + configFile + " validation result: " + isValid);
    }

    public void bad_case_14() {
        int attemptNumber = 3;
        String operationName = "database_backup";
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info(String.format("Attempt %d for operation %s", attemptNumber, operationName));
    }

    public void bad_case_15() {
        String username = "admin";
        String ipAddress = "10.0.0.1";
        String timestamp = "2023-10-15T14:30:45Z";
        StringBuilder loginInfo = new StringBuilder();
        loginInfo.append("Login at ").append(timestamp);
        loginInfo.append(" from IP ").append(ipAddress);
        loginInfo.append(" for user ").append(username);
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info(loginInfo.toString());
    }

    // True Negative Examples (Secure/Efficient Code)

    public void good_case_1() {
        String username = "user123";
        int loginAttempts = 5;
        // ok: java-avoid-string-formatting-in-logging
        logger.debug("User {} has attempted to login {} times", username, loginAttempts);
    }

    public void good_case_2() {
        String ipAddress = "192.168.1.1";
        int port = 8080;
        // ok: java-avoid-string-formatting-in-logging
        logger.info("Connection from {} on port {}", ipAddress, port);
    }

    public void good_case_3() {
        String filename = "config.xml";
        long fileSize = 1024;
        // ok: java-avoid-string-formatting-in-logging
        logger.warn("File {} has size {} bytes", filename, fileSize);
    }

    public void good_case_4() {
        String userId = "admin";
        String action = "DELETE";
        String resource = "users/123";
        // ok: java-avoid-string-formatting-in-logging
        logger.error("User {} attempted {} on resource {}", userId, action, resource);
    }

    public void good_case_5() {
        int statusCode = 404;
        String path = "/api/users";
        // ok: java-avoid-string-formatting-in-logging
        logger.info("HTTP {} response for path {}", statusCode, path);
    }

    public void good_case_6() {
        String transactionId = UUID.randomUUID().toString();
        double amount = 199.99;
        // ok: java-avoid-string-formatting-in-logging
        logger.debug("Processing transaction {} for ${}", transactionId, amount);
    }

    public void good_case_7() {
        int recordsProcessed = 1500;
        long processingTime = 3500;
        // ok: java-avoid-string-formatting-in-logging
        logger.info("Batch job completed: {} records in {}ms", recordsProcessed, processingTime);
    }

    public void good_case_8() {
        String username = "jsmith";
        int permissionLevel = 3;
        // ok: java-avoid-string-formatting-in-logging
        logger.debug("Checking authorization for user {} with permission level {}", username, permissionLevel);
    }

    public void good_case_9() {
        String databaseName = "customers";
        int connectionPoolSize = 10;
        // ok: java-avoid-string-formatting-in-logging
        logger.info("Database connection established to {} with pool size {}", databaseName, connectionPoolSize);
    }

    public void good_case_10() {
        String methodName = "processPayment";
        long executionTime = 250;
        // ok: java-avoid-string-formatting-in-logging
        logger.debug("Method {} executed in {}ms", methodName, executionTime);
    }

    public void good_case_11() {
        String serviceName = "AuthService";
        String errorCode = "AUTH_FAILED";
        Exception e = new RuntimeException("Authentication failed");
        // ok: java-avoid-string-formatting-in-logging
        logger.error("{} error: {}", serviceName, errorCode, e);
    }

    public void good_case_12() {
        int activeUsers = 1250;
        int totalCapacity = 2000;
        // ok: java-avoid-string-formatting-in-logging
        logger.info("System load: {}/{} active users", activeUsers, totalCapacity);
    }

    public void good_case_13() {
        String configFile = "app-config.json";
        boolean isValid = false;
        // ok: java-avoid-string-formatting-in-logging
        logger.warn("Configuration file {} validation result: {}", configFile, isValid);
    }

    public void good_case_14() {
        // Conditional logging that avoids unnecessary string formatting
        String operationName = "database_backup";
        int attemptNumber = 3;
        // ok: java-avoid-string-formatting-in-logging
        if (logger.isInfoEnabled()) {
            logger.info("Attempt {} for operation {}", attemptNumber, operationName);
        }
    }

    public void good_case_15() {
        // Using multiple parameters with SLF4J
        String username = "admin";
        String ipAddress = "10.0.0.1";
        String timestamp = "2023-10-15T14:30:45Z";
        // ok: java-avoid-string-formatting-in-logging
        logger.info("Login at {} from IP {} for user {}", timestamp, ipAddress, username);
    }
}
// {/fact}