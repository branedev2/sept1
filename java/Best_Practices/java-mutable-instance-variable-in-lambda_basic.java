import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

public class MutableInstanceVariableInLambdaExamples {

    // True Positive Examples (Vulnerable Code)

    // Example 1: Basic mutable instance variable in Lambda handler
    private List<String> requestHistory = new ArrayList<>();

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1(Map<String, Object> input, Context context) {
        // ruleid: java-mutable-instance-variable-in-lambda
        RequestHandler<Map<String, Object>, String> handler = (request, ctx) -> {
            requestHistory.add(request.toString()); // Using mutable instance variable
            return "Processed request: " + request.toString();
        };
        
        String result = handler.handleRequest(input, context);
        System.out.println(result);
    }

    // Example 2: Mutable counter in Lambda function
    private int requestCount = 0;

    public void bad_case_2(Map<String, Object> input, Context context) {
        Function<Map<String, Object>, String> processor = request -> {
            // ruleid: java-mutable-instance-variable-in-lambda
            requestCount++; // Modifying mutable instance variable
            return "Request #" + requestCount + ": " + request.toString();
        };
        
        String result = processor.apply(input);
        System.out.println(result);
    }

    // Example 3: Mutable map for caching in Lambda
    private Map<String, Object> cache = new HashMap<>();

    public void bad_case_3(String key, Context context) {
        Function<String, Object> cacheRetriever = k -> {
            // ruleid: java-mutable-instance-variable-in-lambda
            if (!cache.containsKey(k)) {
                cache.put(k, fetchDataFromDatabase(k)); // Modifying mutable instance variable
            }
            return cache.get(k);
        };
        
        Object result = cacheRetriever.apply(key);
        System.out.println("Retrieved: " + result);
    }

    // Example 4: Mutable list for collecting errors
    private List<String> errorLog = new ArrayList<>();

    public void bad_case_4(List<String> inputs, Context context) {
        Consumer<String> processor = input -> {
            try {
                processData(input);
            } catch (Exception e) {
                // ruleid: java-mutable-instance-variable-in-lambda
                errorLog.add("Error processing " + input + ": " + e.getMessage()); // Modifying mutable instance variable
            }
        };
        
        inputs.forEach(processor);
        System.out.println("Errors: " + errorLog.size());
    }

    // Example 5: Mutable flag for tracking state
    private boolean hasProcessedData = false;

    public void bad_case_5(String input, Context context) {
        Runnable processor = () -> {
            processData(input);
            // ruleid: java-mutable-instance-variable-in-lambda
            hasProcessedData = true; // Modifying mutable instance variable
        };
        
        processor.run();
        if (hasProcessedData) {
            System.out.println("Data processed successfully");
        }
    }

    // Example 6: Mutable counter with complex logic
    private int successCount = 0;
    private int failureCount = 0;

    public void bad_case_6(List<String> inputs, Context context) {
        Function<String, Boolean> processor = input -> {
            try {
                boolean result = processData(input);
                if (result) {
                    // ruleid: java-mutable-instance-variable-in-lambda
                    successCount++; // Modifying mutable instance variable
                    return true;
                } else {
                    // ruleid: java-mutable-instance-variable-in-lambda
                    failureCount++; // Modifying mutable instance variable
                    return false;
                }
            } catch (Exception e) {
                // ruleid: java-mutable-instance-variable-in-lambda
                failureCount++; // Modifying mutable instance variable
                return false;
            }
        };
        
        inputs.forEach(processor::apply);
        System.out.println("Success: " + successCount + ", Failures: " + failureCount);
    }

    // Example 7: Mutable StringBuilder for logging
    private StringBuilder logBuilder = new StringBuilder();

    public void bad_case_7(List<String> inputs, Context context) {
        Consumer<String> logger = input -> {
            // ruleid: java-mutable-instance-variable-in-lambda
            logBuilder.append("Processing: ").append(input).append("\n"); // Modifying mutable instance variable
            processData(input);
        };
        
        inputs.forEach(logger);
        System.out.println("Log:\n" + logBuilder.toString());
    }

    // Example 8: Mutable map for user sessions
    private Map<String, UserSession> userSessions = new HashMap<>();

    public void bad_case_8(String userId, Context context) {
        Function<String, UserSession> sessionProvider = id -> {
            // ruleid: java-mutable-instance-variable-in-lambda
            if (!userSessions.containsKey(id)) {
                userSessions.put(id, new UserSession(id)); // Modifying mutable instance variable
            }
            return userSessions.get(id);
        };
        
        UserSession session = sessionProvider.apply(userId);
        System.out.println("Session: " + session);
    }

    // Example 9: Mutable list with conditional logic
    private List<String> validatedInputs = new ArrayList<>();
    private List<String> invalidInputs = new ArrayList<>();

    public void bad_case_9(List<String> inputs, Context context) {
        Consumer<String> validator = input -> {
            if (isValid(input)) {
                // ruleid: java-mutable-instance-variable-in-lambda
                validatedInputs.add(input); // Modifying mutable instance variable
            } else {
                // ruleid: java-mutable-instance-variable-in-lambda
                invalidInputs.add(input); // Modifying mutable instance variable
            }
        };
        
        inputs.forEach(validator);
        System.out.println("Valid: " + validatedInputs.size() + ", Invalid: " + invalidInputs.size());
    }

    // Example 10: Mutable object with complex state
    private ProcessingState state = new ProcessingState();

    public void bad_case_10(List<String> inputs, Context context) {
        Consumer<String> processor = input -> {
            // ruleid: java-mutable-instance-variable-in-lambda
            state.incrementProcessed(); // Modifying mutable instance variable
            if (processData(input)) {
                // ruleid: java-mutable-instance-variable-in-lambda
                state.incrementSuccess(); // Modifying mutable instance variable
            } else {
                // ruleid: java-mutable-instance-variable-in-lambda
                state.incrementFailure(); // Modifying mutable instance variable
            }
        };
        
        inputs.forEach(processor);
        System.out.println("State: " + state);
    }

    // Example 11: Mutable timestamp for tracking
    private long lastProcessedTimestamp = 0;

    public void bad_case_11(String input, Context context) {
        Supplier<String> processor = () -> {
            String result = processData(input) ? "success" : "failure";
            // ruleid: java-mutable-instance-variable-in-lambda
            lastProcessedTimestamp = System.currentTimeMillis(); // Modifying mutable instance variable
            return result;
        };
        
        String result = processor.get();
        System.out.println("Result: " + result + ", Time: " + lastProcessedTimestamp);
    }

    // Example 12: Mutable array for collecting results
    private String[] results = new String[100];
    private int resultIndex = 0;

    public void bad_case_12(List<String> inputs, Context context) {
        Function<String, Boolean> processor = input -> {
            String result = processData(input) ? "success" : "failure";
            // ruleid: java-mutable-instance-variable-in-lambda
            results[resultIndex++] = result; // Modifying mutable instance variables
            return true;
        };
        
        inputs.forEach(processor::apply);
        System.out.println("Processed " + resultIndex + " items");
    }

    // Example 13: Mutable nested data structure
    private Map<String, List<String>> categoryData = new HashMap<>();

    public void bad_case_13(String category, String item, Context context) {
        Consumer<String> categorizer = cat -> {
            // ruleid: java-mutable-instance-variable-in-lambda
            if (!categoryData.containsKey(cat)) {
                categoryData.put(cat, new ArrayList<>()); // Modifying mutable instance variable
            }
            // ruleid: java-mutable-instance-variable-in-lambda
            categoryData.get(cat).add(item); // Modifying mutable instance variable
        };
        
        categorizer.accept(category);
        System.out.println("Categories: " + categoryData.keySet());
    }

    // Example 14: Mutable custom object with state
    private RequestStats stats = new RequestStats();

    public void bad_case_14(String input, Context context) {
        Function<String, String> processor = req -> {
            // ruleid: java-mutable-instance-variable-in-lambda
            stats.recordRequest(); // Modifying mutable instance variable
            try {
                String result = processRequest(req);
                // ruleid: java-mutable-instance-variable-in-lambda
                stats.recordSuccess(); // Modifying mutable instance variable
                return result;
            } catch (Exception e) {
                // ruleid: java-mutable-instance-variable-in-lambda
                stats.recordFailure(e); // Modifying mutable instance variable
                return "Error: " + e.getMessage();
            }
        };
        
        String result = processor.apply(input);
        System.out.println("Result: " + result + ", Stats: " + stats);
    }

    // Example 15: Mutable configuration state
    private Configuration config = new Configuration();

    public void bad_case_15(Map<String, String> configUpdates, Context context) {
        Consumer<Map.Entry<String, String>> configUpdater = entry -> {
            // ruleid: java-mutable-instance-variable-in-lambda
            config.setProperty(entry.getKey(), entry.getValue()); // Modifying mutable instance variable
        };
        
        configUpdates.entrySet().forEach(configUpdater);
        System.out.println("Updated configuration: " + config);
    }

    // True Negative Examples (Safe Code)

    // Example 1: Using method-local variable instead of instance variable
    public void good_case_1(Map<String, Object> input, Context context) {
        List<String> requestHistory = new ArrayList<>(); // Method-local variable
        
        RequestHandler<Map<String, Object>, String> handler = (request, ctx) -> {
            // ok: java-mutable-instance-variable-in-lambda
            requestHistory.add(request.toString()); // Using method-local variable
            return "Processed request: " + request.toString();
        };
        
        String result = handler.handleRequest(input, context);
        System.out.println(result);
        System.out.println("History size: " + requestHistory.size());
    }

    // Example 2: Using method-local counter
    public void good_case_2(Map<String, Object> input, Context context) {
        final int[] requestCount = {0}; // Method-local variable
        
        Function<Map<String, Object>, String> processor = request -> {
            // ok: java-mutable-instance-variable-in-lambda
            requestCount[0]++; // Modifying method-local variable
            return "Request #" + requestCount[0] + ": " + request.toString();
        };
        
        String result = processor.apply(input);
        System.out.println(result);
    }

    // Example 3: Using method-local map for caching
    public void good_case_3(String key, Context context) {
        Map<String, Object> cache = new HashMap<>(); // Method-local variable
        
        Function<String, Object> cacheRetriever = k -> {
            // ok: java-mutable-instance-variable-in-lambda
            if (!cache.containsKey(k)) {
                cache.put(k, fetchDataFromDatabase(k)); // Modifying method-local variable
            }
            return cache.get(k);
        };
        
        Object result = cacheRetriever.apply(key);
        System.out.println("Retrieved: " + result);
    }

    // Example 4: Using method-local list for collecting errors
    public void good_case_4(List<String> inputs, Context context) {
        List<String> errorLog = new ArrayList<>(); // Method-local variable
        
        Consumer<String> processor = input -> {
            try {
                processData(input);
            } catch (Exception e) {
                // ok: java-mutable-instance-variable-in-lambda
                errorLog.add("Error processing " + input + ": " + e.getMessage()); // Modifying method-local variable
            }
        };
        
        inputs.forEach(processor);
        System.out.println("Errors: " + errorLog.size());
    }

    // Example 5: Using method-local flag for tracking state
    public void good_case_5(String input, Context context) {
        final boolean[] hasProcessedData = {false}; // Method-local variable
        
        Runnable processor = () -> {
            processData(input);
            // ok: java-mutable-instance-variable-in-lambda
            hasProcessedData[0] = true; // Modifying method-local variable
        };
        
        processor.run();
        if (hasProcessedData[0]) {
            System.out.println("Data processed successfully");
        }
    }

    // Example 6: Using method-local counters with complex logic
    public void good_case_6(List<String> inputs, Context context) {
        final int[] successCount = {0}; // Method-local variable
        final int[] failureCount = {0}; // Method-local variable
        
        Function<String, Boolean> processor = input -> {
            try {
                boolean result = processData(input);
                if (result) {
                    // ok: java-mutable-instance-variable-in-lambda
                    successCount[0]++; // Modifying method-local variable
                    return true;
                } else {
                    // ok: java-mutable-instance-variable-in-lambda
                    failureCount[0]++; // Modifying method-local variable
                    return false;
                }
            } catch (Exception e) {
                // ok: java-mutable-instance-variable-in-lambda
                failureCount[0]++; // Modifying method-local variable
                return false;
            }
        };
        
        inputs.forEach(processor::apply);
        System.out.println("Success: " + successCount[0] + ", Failures: " + failureCount[0]);
    }

    // Example 7: Using method-local StringBuilder for logging
    public void good_case_7(List<String> inputs, Context context) {
        StringBuilder logBuilder = new StringBuilder(); // Method-local variable
        
        Consumer<String> logger = input -> {
            // ok: java-mutable-instance-variable-in-lambda
            logBuilder.append("Processing: ").append(input).append("\n"); // Modifying method-local variable
            processData(input);
        };
        
        inputs.forEach(logger);
        System.out.println("Log:\n" + logBuilder.toString());
    }

    // Example 8: Using method-local map for user sessions
    public void good_case_8(String userId, Context context) {
        Map<String, UserSession> userSessions = new HashMap<>(); // Method-local variable
        
        Function<String, UserSession> sessionProvider = id -> {
            // ok: java-mutable-instance-variable-in-lambda
            if (!userSessions.containsKey(id)) {
                userSessions.put(id, new UserSession(id)); // Modifying method-local variable
            }
            return userSessions.get(id);
        };
        
        UserSession session = sessionProvider.apply(userId);
        System.out.println("Session: " + session);
    }

    // Example 9: Using method-local lists with conditional logic
    public void good_case_9(List<String> inputs, Context context) {
        List<String> validatedInputs = new ArrayList<>(); // Method-local variable
        List<String> invalidInputs = new ArrayList<>(); // Method-local variable
        
        Consumer<String> validator = input -> {
            if (isValid(input)) {
                // ok: java-mutable-instance-variable-in-lambda
                validatedInputs.add(input); // Modifying method-local variable
            } else {
                // ok: java-mutable-instance-variable-in-lambda
                invalidInputs.add(input); // Modifying method-local variable
            }
        };
        
        inputs.forEach(validator);
        System.out.println("Valid: " + validatedInputs.size() + ", Invalid: " + invalidInputs.size());
    }

    // Example 10: Using method-local object with complex state
    public void good_case_10(List<String> inputs, Context context) {
        ProcessingState state = new ProcessingState(); // Method-local variable
        
        Consumer<String> processor = input -> {
            // ok: java-mutable-instance-variable-in-lambda
            state.incrementProcessed(); // Modifying method-local variable
            if (processData(input)) {
                // ok: java-mutable-instance-variable-in-lambda
                state.incrementSuccess(); // Modifying method-local variable
            } else {
                // ok: java-mutable-instance-variable-in-lambda
                state.incrementFailure(); // Modifying method-local variable
            }
        };
        
        inputs.forEach(processor);
        System.out.println("State: " + state);
    }

    // Example 11: Using method-local timestamp for tracking
    public void good_case_11(String input, Context context) {
        final long[] lastProcessedTimestamp = {0}; // Method-local variable
        
        Supplier<String> processor = () -> {
            String result = processData(input) ? "success" : "failure";
            // ok: java-mutable-instance-variable-in-lambda
            lastProcessedTimestamp[0] = System.currentTimeMillis(); // Modifying method-local variable
            return result;
        };
        
        String result = processor.get();
        System.out.println("Result: " + result + ", Time: " + lastProcessedTimestamp[0]);
    }

    // Example 12: Using method-local array for collecting results
    public void good_case_12(List<String> inputs, Context context) {
        String[] results = new String[100]; // Method-local variable
        final int[] resultIndex = {0}; // Method-local variable
        
        Function<String, Boolean> processor = input -> {
            String result = processData(input) ? "success" : "failure";
            // ok: java-mutable-instance-variable-in-lambda
            results[resultIndex[0]++] = result; // Modifying method-local variables
            return true;
        };
        
        inputs.forEach(processor::apply);
        System.out.println("Processed " + resultIndex[0] + " items");
    }

    // Example 13: Using method-local nested data structure
    public void good_case_13(String category, String item, Context context) {
        Map<String, List<String>> categoryData = new HashMap<>(); // Method-local variable
        
        Consumer<String> categorizer = cat -> {
            // ok: java-mutable-instance-variable-in-lambda
            if (!categoryData.containsKey(cat)) {
                categoryData.put(cat, new ArrayList<>()); // Modifying method-local variable
            }
            // ok: java-mutable-instance-variable-in-lambda
            categoryData.get(cat).add(item); // Modifying method-local variable
        };
        
        categorizer.accept(category);
        System.out.println("Categories: " + categoryData.keySet());
    }

    // Example 14: Using method-local custom object with state
    public void good_case_14(String input, Context context) {
        RequestStats stats = new RequestStats(); // Method-local variable
        
        Function<String, String> processor = req -> {
            // ok: java-mutable-instance-variable-in-lambda
            stats.recordRequest(); // Modifying method-local variable
            try {
                String result = processRequest(req);
                // ok: java-mutable-instance-variable-in-lambda
                stats.recordSuccess(); // Modifying method-local variable
                return result;
            } catch (Exception e) {
                // ok: java-mutable-instance-variable-in-lambda
                stats.recordFailure(e); // Modifying method-local variable
                return "Error: " + e.getMessage();
            }
        };
        
        String result = processor.apply(input);
        System.out.println("Result: " + result + ", Stats: " + stats);
    }

    // Example 15: Using method-local configuration state
    public void good_case_15(Map<String, String> configUpdates, Context context) {
        Configuration config = new Configuration(); // Method-local variable
        
        Consumer<Map.Entry<String, String>> configUpdater = entry -> {
            // ok: java-mutable-instance-variable-in-lambda
            config.setProperty(entry.getKey(), entry.getValue()); // Modifying method-local variable
        };
        
        configUpdates.entrySet().forEach(configUpdater);
        System.out.println("Updated configuration: " + config);
    }

    // Helper methods and classes
    private Object fetchDataFromDatabase(String key) {
        return "Data for " + key;
    }
    
    private boolean processData(String input) {
        return input != null && !input.isEmpty();
    }
    
    private String processRequest(String request) {
        return "Processed: " + request;
    }
    
    private boolean isValid(String input) {
        return input != null && input.length() > 3;
    }
    
    private static class UserSession {
        private String userId;
        
        public UserSession(String userId) {
            this.userId = userId;
        }
        
        @Override
        public String toString() {
            return "UserSession{userId='" + userId + "'}";
        }
    }
    
    private static class ProcessingState {
        private int processed = 0;
        private int success = 0;
        private int failure = 0;
        
        public void incrementProcessed() {
            processed++;
        }
        
        public void incrementSuccess() {
            success++;
        }
        
        public void incrementFailure() {
            failure++;
        }
        
        @Override
        public String toString() {
            return "ProcessingState{processed=" + processed + ", success=" + success + ", failure=" + failure + "}";
        }
    }
    
    private static class RequestStats {
        private int requests = 0;
        private int successes = 0;
        private int failures = 0;
        
        public void recordRequest() {
            requests++;
        }
        
        public void recordSuccess() {
            successes++;
        }
        
        public void recordFailure(Exception e) {
            failures++;
        }
        
        @Override
        public String toString() {
            return "RequestStats{requests=" + requests + ", successes=" + successes + ", failures=" + failures + "}";
        }
    }
    
    private static class Configuration {
        private Map<String, String> properties = new HashMap<>();
        
        public void setProperty(String key, String value) {
            properties.put(key, value);
        }
        
        @Override
        public String toString() {
            return "Configuration{properties=" + properties + "}";
        }
    }
}
// {/fact}