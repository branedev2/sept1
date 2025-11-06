package com.example.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

public class LoggingExamples {
    private static final Logger logger = LoggerFactory.getLogger(LoggingExamples.class);
    
    // True Positives (Vulnerable/Inefficient Code)
    
// {fact rule=inefficient-cpu-computation@v1.0 defects=1}
    public void bad_case_1() {
        String userId = "user-" + UUID.randomUUID().toString();
        int score = 95;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.debug("User " + userId + " scored " + score + " points");
    }
    
    public void bad_case_2() {
        String transactionId = UUID.randomUUID().toString();
        double amount = 1299.99;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info(String.format("Transaction %s completed for $%.2f", transactionId, amount));
    }
    
    public void bad_case_3() {
        String username = "john_doe";
        int loginAttempts = 3;
        StringBuilder sb = new StringBuilder();
        sb.append("Failed login for user ");
        sb.append(username);
        sb.append(", attempts: ");
        sb.append(loginAttempts);
        // ruleid: java-avoid-string-formatting-in-logging
        logger.warn(sb.toString());
    }
    
    public void bad_case_4() {
        String productId = "PROD-12345";
        int quantity = 10;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.error("Failed to update inventory for product " + productId + " with quantity " + quantity);
    }
    
    public void bad_case_5() {
        String endpoint = "/api/users";
        int statusCode = 404;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info(String.format("Request to %s returned status code %d", endpoint, statusCode));
    }
    
    public void bad_case_6() {
        String operation = "database_backup";
        long duration = 3600;
        StringBuilder message = new StringBuilder();
        message.append("Operation ");
        message.append(operation);
        message.append(" took ");
        message.append(duration);
        message.append(" seconds");
        // ruleid: java-avoid-string-formatting-in-logging
        logger.debug(message.toString());
    }
    
    public void bad_case_7() {
        String clientIp = "192.168.1.1";
        String resource = "/secure/admin";
        // ruleid: java-avoid-string-formatting-in-logging
        logger.warn("Unauthorized access attempt from " + clientIp + " to resource " + resource);
    }
    
    public void bad_case_8() {
        int connections = 150;
        int maxConnections = 200;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info(String.format("Current connection pool status: %d/%d", connections, maxConnections));
    }
    
    public void bad_case_9() {
        String filename = "large_report.pdf";
        long filesize = 15728640;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.debug("File " + filename + " generated with size " + filesize + " bytes");
    }
    
    public void bad_case_10() {
        String username = "admin";
        String action = "DELETE";
        String resource = "users/john";
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info(String.format("User %s performed %s operation on %s", username, action, resource));
    }
    
    public void bad_case_11() {
        int errorCode = 500;
        String errorMessage = "Internal server error";
        StringBuilder sb = new StringBuilder();
        sb.append("Error occurred: code=");
        sb.append(errorCode);
        sb.append(", message=");
        sb.append(errorMessage);
        // ruleid: java-avoid-string-formatting-in-logging
        logger.error(sb.toString());
    }
    
    public void bad_case_12() {
        String serviceName = "PaymentService";
        long responseTime = 1500;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.warn("Service " + serviceName + " response time exceeded threshold: " + responseTime + "ms");
    }
    
    public void bad_case_13() {
        String jobId = "JOB-" + ThreadLocalRandom.current().nextInt(10000);
        int progress = 75;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info(String.format("Job %s is %d%% complete", jobId, progress));
    }
    
    public void bad_case_14() {
        String configName = "app.properties";
        String configPath = "/etc/app/config/";
        // ruleid: java-avoid-string-formatting-in-logging
        logger.debug("Loading configuration from " + configPath + configName);
    }
    
    public void bad_case_15() {
        int successCount = 95;
        int failureCount = 5;
        int totalCount = successCount + failureCount;
        // ruleid: java-avoid-string-formatting-in-logging
        logger.info(String.format("Batch processing complete: %d succeeded, %d failed, %d total", 
                    successCount, failureCount, totalCount));
    }
    
    // True Negatives (Safe/Efficient Code)
    
    public void good_case_1() {
        String userId = "user-" + UUID.randomUUID().toString();
        int score = 95;
        // ok: java-avoid-string-formatting-in-logging
        logger.debug("User {} scored {} points", userId, score);
    }
    
    public void good_case_2() {
        String transactionId = UUID.randomUUID().toString();
        double amount = 1299.99;
        // ok: java-avoid-string-formatting-in-logging
        logger.info("Transaction {} completed for ${}", transactionId, amount);
    }
    
    public void good_case_3() {
        String username = "john_doe";
        int loginAttempts = 3;
        // ok: java-avoid-string-formatting-in-logging
        logger.warn("Failed login for user {}, attempts: {}", username, loginAttempts);
    }
    
    public void good_case_4() {
        String productId = "PROD-12345";
        int quantity = 10;
        // ok: java-avoid-string-formatting-in-logging
        logger.error("Failed to update inventory for product {} with quantity {}", productId, quantity);
    }
    
    public void good_case_5() {
        String endpoint = "/api/users";
        int statusCode = 404;
        // ok: java-avoid-string-formatting-in-logging
        logger.info("Request to {} returned status code {}", endpoint, statusCode);
    }
    
    public void good_case_6() {
        String operation = "database_backup";
        long duration = 3600;
        // ok: java-avoid-string-formatting-in-logging
        logger.debug("Operation {} took {} seconds", operation, duration);
    }
    
    public void good_case_7() {
        String clientIp = "192.168.1.1";
        String resource = "/secure/admin";
        // ok: java-avoid-string-formatting-in-logging
        logger.warn("Unauthorized access attempt from {} to resource {}", clientIp, resource);
    }
    
    public void good_case_8() {
        int connections = 150;
        int maxConnections = 200;
        // ok: java-avoid-string-formatting-in-logging
        logger.info("Current connection pool status: {}/{}", connections, maxConnections);
    }
    
    public void good_case_9() {
        String filename = "large_report.pdf";
        long filesize = 15728640;
        // ok: java-avoid-string-formatting-in-logging
        logger.debug("File {} generated with size {} bytes", filename, filesize);
    }
    
    public void good_case_10() {
        String username = "admin";
        String action = "DELETE";
        String resource = "users/john";
        // ok: java-avoid-string-formatting-in-logging
        logger.info("User {} performed {} operation on {}", username, action, resource);
    }
    
    public void good_case_11() {
        int errorCode = 500;
        String errorMessage = "Internal server error";
        // ok: java-avoid-string-formatting-in-logging
        logger.error("Error occurred: code={}, message={}", errorCode, errorMessage);
    }
    
    public void good_case_12() {
        String serviceName = "PaymentService";
        long responseTime = 1500;
        // ok: java-avoid-string-formatting-in-logging
        logger.warn("Service {} response time exceeded threshold: {}ms", serviceName, responseTime);
    }
    
    public void good_case_13() {
        String jobId = "JOB-" + ThreadLocalRandom.current().nextInt(10000);
        int progress = 75;
        // ok: java-avoid-string-formatting-in-logging
        logger.info("Job {} is {}% complete", jobId, progress);
    }
    
    public void good_case_14() {
        String configName = "app.properties";
        String configPath = "/etc/app/config/";
        // ok: java-avoid-string-formatting-in-logging
        logger.debug("Loading configuration from {}{}", configPath, configName);
    }
    
    public void good_case_15() {
        int successCount = 95;
        int failureCount = 5;
        int totalCount = successCount + failureCount;
        // ok: java-avoid-string-formatting-in-logging
        logger.info("Batch processing complete: {} succeeded, {} failed, {} total", 
                   successCount, failureCount, totalCount);
    }
}
// {/fact}