import com.evanlennick.retry4j.CallExecutor;
import com.evanlennick.retry4j.AsyncCallExecutor;
import com.evanlennick.retry4j.config.RetryConfig;
import com.evanlennick.retry4j.config.RetryConfigBuilder;
import com.evanlennick.retry4j.Status;
import com.evanlennick.retry4j.CallExecutorBuilder;

import java.util.concurrent.Callable;
import java.time.temporal.ChronoUnit;
import java.util.function.Function;
import javax.inject.Singleton;
import org.springframework.stereotype.Service;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RestController;
import javax.ejb.Stateless;

// TRUE POSITIVES - Vulnerable code examples

// Example 1: Basic singleton with CallExecutor as instance variable
@Singleton
public class BadCase1 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<String> callExecutor = new CallExecutor<>();
    
    public String executeCall(Callable<String> callable) {
        Status<String> status = callExecutor.execute(callable);
        return status.getResult();
    }
}

// Example 2: Spring service with CallExecutor
@Service
public class BadCase2 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Boolean> callExecutor = new CallExecutorBuilder().config(new RetryConfigBuilder().build()).build();
    
    public boolean performOperation(Callable<Boolean> operation) {
        Status<Boolean> status = callExecutor.execute(operation);
        return status.getResult();
    }
}

// Example 3: Spring component with configured CallExecutor
@Component
public class BadCase3 {
    private RetryConfig config = new RetryConfigBuilder()
            .retryOnAnyException()
            .withMaxNumberOfTries(3)
            .withDelayBetweenTries(1000, ChronoUnit.MILLIS)
            .build();
            
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Object> callExecutor = new CallExecutor<>(config);
    
    public <T> T execute(Callable<T> task) {
        Status<T> status = (Status<T>) callExecutor.execute(task);
        return status.getResult();
    }
}

// Example 4: REST controller with CallExecutor
@RestController
public class BadCase4 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<String> callExecutor = new CallExecutor<>();
    
    public String handleRequest(String requestId) {
        return callExecutor.execute(() -> processRequest(requestId)).getResult();
    }
    
    private String processRequest(String requestId) {
        return "Processed: " + requestId;
    }
}

// Example 5: Stateless EJB with CallExecutor
@Stateless
public class BadCase5 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Integer> callExecutor = new CallExecutor<>();
    
    public int calculateValue(int input) {
        return callExecutor.execute(() -> performCalculation(input)).getResult();
    }
    
    private int performCalculation(int input) {
        return input * 2;
    }
}

// Example 6: Singleton with configured CallExecutor
@Singleton
public class BadCase6 {
    private RetryConfig config = new RetryConfigBuilder()
            .retryOnSpecificExceptions(IllegalArgumentException.class)
            .withMaxNumberOfTries(5)
            .withFixedBackoff()
            .build();
            
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<String> callExecutor = new CallExecutor<>(config);
    
    public String processData(String data) {
        return callExecutor.execute(() -> transform(data)).getResult();
    }
    
    private String transform(String data) {
        return data.toUpperCase();
    }
}

// Example 7: Service with CallExecutor and exception handling
@Service
public class BadCase7 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Double> callExecutor = new CallExecutor<>();
    
    public Double safeCalculation(double value) {
        try {
            Status<Double> status = callExecutor.execute(() -> Math.sqrt(value));
            return status.getResult();
        } catch (Exception e) {
            return 0.0;
        }
    }
}

// Example 8: Component with multiple CallExecutors
@Component
public class BadCase8 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<String> stringExecutor = new CallExecutor<>();
    
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Integer> intExecutor = new CallExecutor<>();
    
    public String processString(String input) {
        return stringExecutor.execute(() -> input + "-processed").getResult();
    }
    
    public int processInt(int input) {
        return intExecutor.execute(() -> input * 10).getResult();
    }
}

// Example 9: Singleton with lazy initialization of CallExecutor
@Singleton
public class BadCase9 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Long> callExecutor;
    
    public Long execute(Callable<Long> task) {
        if (callExecutor == null) {
            callExecutor = new CallExecutor<>();
        }
        return callExecutor.execute(task).getResult();
    }
}

// Example 10: Service with CallExecutor in a field initialization block
@Service
public class BadCase10 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<String> callExecutor;
    
    {
        RetryConfig config = new RetryConfigBuilder()
                .retryOnAnyException()
                .withMaxNumberOfTries(3)
                .build();
        callExecutor = new CallExecutor<>(config);
    }
    
    public String process(Callable<String> task) {
        return callExecutor.execute(task).getResult();
    }
}

// Example 11: Component with CallExecutor initialized in constructor
@Component
public class BadCase11 {
    // ruleid: java-call-executor-not-thread-safe
    private final CallExecutor<Boolean> callExecutor;
    
    public BadCase11() {
        callExecutor = new CallExecutor<>();
    }
    
    public boolean execute(Callable<Boolean> task) {
        return callExecutor.execute(task).getResult();
    }
}

// Example 12: Singleton with generic CallExecutor
@Singleton
public class BadCase12 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Object> callExecutor = new CallExecutor<>();
    
    public <T> T execute(Callable<T> task) {
        @SuppressWarnings("unchecked")
        Status<T> status = (Status<T>) callExecutor.execute((Callable<Object>) task);
        return status.getResult();
    }
}

// Example 13: Service with CallExecutor and custom exception handling
@Service
public class BadCase13 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<String> callExecutor = new CallExecutor<>();
    
    public String executeWithFallback(Callable<String> task, String fallback) {
        try {
            return callExecutor.execute(task).getResult();
        } catch (Exception e) {
            return fallback;
        }
    }
}

// Example 14: Component with CallExecutor and result transformation
@Component
public class BadCase14 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Integer> callExecutor = new CallExecutor<>();
    
    public String executeAndTransform(Callable<Integer> task) {
        Status<Integer> status = callExecutor.execute(task);
        Integer result = status.getResult();
        return "Result: " + result;
    }
}

// Example 15: REST controller with configured CallExecutor
@RestController
public class BadCase15 {
    private RetryConfig config = new RetryConfigBuilder()
            .retryOnAnyException()
            .withMaxNumberOfTries(5)
            .withExponentialBackoff()
            .build();
            
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<String> callExecutor = new CallExecutor<>(config);
    
    public String handleApiCall(String input) {
        return callExecutor.execute(() -> callExternalApi(input)).getResult();
    }
    
    private String callExternalApi(String input) {
        // Simulate API call
        return "API response for: " + input;
    }
}

// TRUE NEGATIVES - Safe code examples

// Example 1: Using AsyncCallExecutor instead of CallExecutor in a singleton
@Singleton
public class GoodCase1 {
    // ok: java-call-executor-not-thread-safe
    private AsyncCallExecutor<String> callExecutor = new AsyncCallExecutor<>();
    
    public void executeCall(Callable<String> callable) {
        callExecutor.execute(callable);
    }
}

// Example 2: Creating CallExecutor locally in method
@Service
public class GoodCase2 {
    public boolean performOperation(Callable<Boolean> operation) {
        // ok: java-call-executor-not-thread-safe
        CallExecutor<Boolean> callExecutor = new CallExecutor<>();
        Status<Boolean> status = callExecutor.execute(operation);
        return status.getResult();
    }
}

// Example 3: Using AsyncCallExecutor in Spring component
@Component
public class GoodCase3 {
    private RetryConfig config = new RetryConfigBuilder()
            .retryOnAnyException()
            .withMaxNumberOfTries(3)
            .withDelayBetweenTries(1000, ChronoUnit.MILLIS)
            .build();
            
    // ok: java-call-executor-not-thread-safe
    private AsyncCallExecutor<Object> callExecutor = new AsyncCallExecutor<>(config);
    
    public <T> void execute(Callable<T> task) {
        callExecutor.execute(task);
    }
}

// Example 4: Using CallExecutor in a non-singleton class
public class GoodCase4 {
    // ok: java-call-executor-not-thread-safe
    private CallExecutor<String> callExecutor = new CallExecutor<>();
    
    public String handleRequest(String requestId) {
        return callExecutor.execute(() -> processRequest(requestId)).getResult();
    }
    
    private String processRequest(String requestId) {
        return "Processed: " + requestId;
    }
}

// Example 5: Creating new CallExecutor for each execution
@Stateless
public class GoodCase5 {
    public int calculateValue(int input) {
        // ok: java-call-executor-not-thread-safe
        CallExecutor<Integer> callExecutor = new CallExecutor<>();
        return callExecutor.execute(() -> performCalculation(input)).getResult();
    }
    
    private int performCalculation(int input) {
        return input * 2;
    }
}

// Example 6: Using AsyncCallExecutor in a singleton
@Singleton
public class GoodCase6 {
    private RetryConfig config = new RetryConfigBuilder()
            .retryOnSpecificExceptions(IllegalArgumentException.class)
            .withMaxNumberOfTries(5)
            .withFixedBackoff()
            .build();
            
    // ok: java-call-executor-not-thread-safe
    private AsyncCallExecutor<String> callExecutor = new AsyncCallExecutor<>(config);
    
    public void processData(String data) {
        callExecutor.execute(() -> transform(data));
    }
    
    private String transform(String data) {
        return data.toUpperCase();
    }
}

// Example 7: Creating CallExecutor in method with configuration
@Service
public class GoodCase7 {
    public Double safeCalculation(double value) {
        RetryConfig config = new RetryConfigBuilder()
                .retryOnAnyException()
                .withMaxNumberOfTries(3)
                .build();
                
        // ok: java-call-executor-not-thread-safe
        CallExecutor<Double> callExecutor = new CallExecutor<>(config);
        
        try {
            Status<Double> status = callExecutor.execute(() -> Math.sqrt(value));
            return status.getResult();
        } catch (Exception e) {
            return 0.0;
        }
    }
}

// Example 8: Using factory method to create CallExecutor
@Component
public class GoodCase8 {
    public String processString(String input) {
        // ok: java-call-executor-not-thread-safe
        CallExecutor<String> executor = createExecutor();
        return executor.execute(() -> input + "-processed").getResult();
    }
    
    private <T> CallExecutor<T> createExecutor() {
        return new CallExecutor<>();
    }
}

// Example 9: Using AsyncCallExecutor with lazy initialization
@Singleton
public class GoodCase9 {
    // ok: java-call-executor-not-thread-safe
    private AsyncCallExecutor<Long> callExecutor;
    
    public void execute(Callable<Long> task) {
        if (callExecutor == null) {
            callExecutor = new AsyncCallExecutor<>();
        }
        callExecutor.execute(task);
    }
}

// Example 10: Method-scoped CallExecutor with custom configuration
@Service
public class GoodCase10 {
    public String process(Callable<String> task) {
        RetryConfig config = new RetryConfigBuilder()
                .retryOnAnyException()
                .withMaxNumberOfTries(3)
                .build();
                
        // ok: java-call-executor-not-thread-safe
        CallExecutor<String> callExecutor = new CallExecutor<>(config);
        return callExecutor.execute(task).getResult();
    }
}

// Example 11: Using ThreadLocal to store CallExecutor
@Component
public class GoodCase11 {
    // ok: java-call-executor-not-thread-safe
    private ThreadLocal<CallExecutor<Boolean>> callExecutorThreadLocal = ThreadLocal.withInitial(() -> new CallExecutor<>());
    
    public boolean execute(Callable<Boolean> task) {
        return callExecutorThreadLocal.get().execute(task).getResult();
    }
}

// Example 12: Creating CallExecutor per execution with generic type
@Singleton
public class GoodCase12 {
    public <T> T execute(Callable<T> task) {
        // ok: java-call-executor-not-thread-safe
        CallExecutor<T> callExecutor = new CallExecutor<>();
        Status<T> status = callExecutor.execute(task);
        return status.getResult();
    }
}

// Example 13: Using AsyncCallExecutor with custom exception handling
@Service
public class GoodCase13 {
    // ok: java-call-executor-not-thread-safe
    private AsyncCallExecutor<String> callExecutor = new AsyncCallExecutor<>();
    
    public void executeWithFallback(Callable<String> task, String fallback) {
        callExecutor.execute(task)
            .whenComplete((status, throwable) -> {
                if (throwable != null) {
                    System.out.println("Fallback: " + fallback);
                } else {
                    System.out.println("Result: " + status.getResult());
                }
            });
    }
}

// Example 14: Method that creates and returns a new CallExecutor
@Component
public class GoodCase14 {
    public <T> CallExecutor<T> createExecutor() {
        // ok: java-call-executor-not-thread-safe
        return new CallExecutor<>();
    }
    
    public String executeTask(String input) {
        CallExecutor<String> executor = createExecutor();
        return executor.execute(() -> input.toUpperCase()).getResult();
    }
}

// Example 15: Using AsyncCallExecutor in REST controller
@RestController
public class GoodCase15 {
    private RetryConfig config = new RetryConfigBuilder()
            .retryOnAnyException()
            .withMaxNumberOfTries(5)
            .withExponentialBackoff()
            .build();
            
    // ok: java-call-executor-not-thread-safe
    private AsyncCallExecutor<String> callExecutor = new AsyncCallExecutor<>(config);
    
    public void handleApiCall(String input) {
        callExecutor.execute(() -> callExternalApi(input))
            .whenComplete((status, throwable) -> {
                if (throwable == null) {
                    System.out.println("API call successful: " + status.getResult());
                }
            });
    }
    
    private String callExternalApi(String input) {
        // Simulate API call
        return "API response for: " + input;
    }
}