// Imports for all examples
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
import jakarta.enterprise.context.ApplicationScoped;
import org.springframework.context.annotation.Scope;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import javax.ejb.Stateless;
import javax.ejb.Stateful;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

// Security Issue: CallExecutor from Retry4j is not thread-safe and can cause race conditions when used in singleton classes

// True Positive Examples (Vulnerable/Insecure Code)

// Example 1: Basic singleton with CallExecutor as instance variable
class bad_case_1 {
    private static final bad_case_1 INSTANCE = new bad_case_1();
    
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Object> executor = new CallExecutor<>();
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_1() {}
    
    public static bad_case_1 getInstance() {
        return INSTANCE;
    }
    
    public Object executeWithRetry(Callable<Object> task) {
        return executor.execute(task).getResult();
    }
}
// {/fact}

// Example 2: Spring @Service singleton with CallExecutor
@Service
class bad_case_2 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<String> retryExecutor = new CallExecutor<>();
    
    public String fetchDataWithRetry(String url) {
        return retryExecutor.execute(() -> callExternalService(url)).getResult();
    }
    
    private String callExternalService(String url) {
        // Implementation omitted
        return "response";
    }
}

// Example 3: Spring @Component with CallExecutor using builder
@Component
class bad_case_3 {
    private RetryConfig config = new RetryConfigBuilder()
            .retryOnSpecificExceptions(RuntimeException.class)
            .withMaxNumberOfTries(3)
            .withDelayBetweenTries(1, ChronoUnit.SECONDS)
            .build();
    
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Object> executor = new CallExecutorBuilder().config(config).build();
    
    public Object processRequest(String requestData) {
        return executor.execute(() -> processData(requestData)).getResult();
    }
    
    private Object processData(String data) {
        // Implementation omitted
        return new Object();
    }
}

// Example 4: REST Controller with CallExecutor
@RestController
class bad_case_4 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Integer> retryExecutor = new CallExecutor<>();
    
    public Integer handleRequest(String requestId) {
        return retryExecutor.execute(() -> processRequest(requestId)).getResult();
    }
    
    private Integer processRequest(String requestId) {
        // Implementation omitted
        return 200;
    }
}

// Example 5: CDI ApplicationScoped bean with CallExecutor
@ApplicationScoped
class bad_case_5 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Boolean> executor = new CallExecutor<>();
    
    public Boolean validateWithRetry(String input) {
        return executor.execute(() -> validate(input)).getResult();
    }
    
    private Boolean validate(String input) {
        // Implementation omitted
        return true;
    }
}

// Example 6: Enum singleton with CallExecutor
enum bad_case_6 {
    INSTANCE;
    
    // ruleid: java-call-executor-not-thread-safe
    private final CallExecutor<String> executor = new CallExecutor<>();
    
    public String executeTask(Callable<String> task) {
        return executor.execute(task).getResult();
    }
}

// Example 7: Double-checked locking singleton with CallExecutor
class bad_case_7 {
    private static volatile bad_case_7 instance;
    
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Long> executor = new CallExecutor<>();
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_7() {}
    
    public static bad_case_7 getInstance() {
        if (instance == null) {
            synchronized (bad_case_7.class) {
                if (instance == null) {
                    instance = new bad_case_7();
                }
            }
        }
        return instance;
    }
    
    public Long executeWithRetry(Callable<Long> task) {
        return executor.execute(task).getResult();
    }
}
// {/fact}

// Example 8: Static holder singleton pattern with CallExecutor
class bad_case_8 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Double> executor = new CallExecutor<>();
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_8() {}
    
    private static class SingletonHolder {
        private static final bad_case_8 INSTANCE = new bad_case_8();
    }
    
    public static bad_case_8 getInstance() {
        return SingletonHolder.INSTANCE;
    }
    
    public Double calculateWithRetry(Callable<Double> calculation) {
        return executor.execute(calculation).getResult();
    }
}
// {/fact}

// Example 9: Spring singleton bean with CallExecutor
@Configuration
class bad_case_9 {
    @Bean
    public ServiceWithExecutor serviceWithExecutor() {
        return new ServiceWithExecutor();
    }
    
    // By default, Spring beans are singletons
    public static class ServiceWithExecutor {
        // ruleid: java-call-executor-not-thread-safe
        private CallExecutor<byte[]> executor = new CallExecutor<>();
        
        public byte[] fetchDataWithRetry(String url) {
            return executor.execute(() -> fetchBinaryData(url)).getResult();
        }
        
        private byte[] fetchBinaryData(String url) {
            // Implementation omitted
            return new byte[0];
        }
    }
}

// Example 10: EJB Singleton with CallExecutor
@javax.ejb.Singleton
class bad_case_10 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Object> executor = new CallExecutor<>();
    
    public Object executeWithRetry(Callable<Object> task) {
        return executor.execute(task).getResult();
    }
}

// Example 11: Lazy initialization holder class pattern with CallExecutor
class bad_case_11 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<String> executor = new CallExecutor<>();
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_11() {}
    
    private static class LazyHolder {
        static final bad_case_11 INSTANCE = new bad_case_11();
    }
    
    public static bad_case_11 getInstance() {
        return LazyHolder.INSTANCE;
    }
    
    public String processWithRetry(String input) {
        return executor.execute(() -> process(input)).getResult();
    }
    
    private String process(String input) {
        // Implementation omitted
        return "processed: " + input;
    }
}
// {/fact}

// Example 12: Spring @Service with explicit singleton scope and CallExecutor
@Service
@Scope(ConfigurableBeanFactory.SCOPE_SINGLETON)
class bad_case_12 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Integer> executor = new CallExecutor<>();
    
    public Integer computeWithRetry(int value) {
        return executor.execute(() -> compute(value)).getResult();
    }
    
    private Integer compute(int value) {
        // Implementation omitted
        return value * 2;
    }
}

// Example 13: CDI Singleton with CallExecutor
@javax.inject.Singleton
class bad_case_13 {
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Boolean> executor = new CallExecutor<>();
    
    public Boolean checkWithRetry(String data) {
        return executor.execute(() -> check(data)).getResult();
    }
    
    private Boolean check(String data) {
        // Implementation omitted
        return data != null && !data.isEmpty();
    }
}

// Example 14: Eager initialization singleton with CallExecutor
class bad_case_14 {
    private static final bad_case_14 INSTANCE = new bad_case_14();
    
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<Float> executor = new CallExecutor<>();
    
// {fact rule=thread-safety-violation@v1.0 defects=1}
    private bad_case_14() {}
    
    public static bad_case_14 getInstance() {
        return INSTANCE;
    }
    
    public Float calculateWithRetry(Callable<Float> calculation) {
        return executor.execute(calculation).getResult();
    }
}
// {/fact}

// Example 15: Spring @Component with CallExecutor and custom configuration
@Component
class bad_case_15 {
    private RetryConfig config = new RetryConfigBuilder()
            .retryOnAnyException()
            .withMaxNumberOfTries(5)
            .withExponentialBackoff()
            .build();
            
    // ruleid: java-call-executor-not-thread-safe
    private CallExecutor<String> executor = new CallExecutorBuilder().config(config).build();
    
    public String executeWithRetry(String input) {
        return executor.execute(() -> processData(input)).getResult();
    }
    
    private String processData(String input) {
        // Implementation omitted
        return "processed: " + input;
    }
}

// True Negative Examples (Safe/Secure Code)

// Example 1: Using AsyncCallExecutor instead of CallExecutor in a singleton
class good_case_1 {
    private static final good_case_1 INSTANCE = new good_case_1();
    
    // ok: java-call-executor-not-thread-safe
    private AsyncCallExecutor<Object> executor = new AsyncCallExecutor<>();
    
// {fact rule=thread-safety-violation@v1.0 defects=0}
    private good_case_1() {}
    
    public static good_case_1 getInstance() {
        return INSTANCE;
    }
    
    public java.util.concurrent.CompletableFuture<Status<Object>> executeWithRetry(Callable<Object> task) {
        return executor.execute(task);
    }
}
// {/fact}

// Example 2: Creating CallExecutor locally in method instead of as instance variable
@Service
class good_case_2 {
    public String fetchDataWithRetry(String url) {
        // ok: java-call-executor-not-thread-safe
        CallExecutor<String> retryExecutor = new CallExecutor<>();
        return retryExecutor.execute(() -> callExternalService(url)).getResult();
    }
    
    private String callExternalService(String url) {
        // Implementation omitted
        return "response";
    }
}

// Example 3: Using AsyncCallExecutor with builder in Spring component
@Component
class good_case_3 {
    private RetryConfig config = new RetryConfigBuilder()
            .retryOnSpecificExceptions(RuntimeException.class)
            .withMaxNumberOfTries(3)
            .withDelayBetweenTries(1, ChronoUnit.SECONDS)
            .build();
    
    // ok: java-call-executor-not-thread-safe
    private AsyncCallExecutor<Object> executor = new AsyncCallExecutorBuilder().config(config).build();
    
    public java.util.concurrent.CompletableFuture<Status<Object>> processRequest(String requestData) {
        return executor.execute(() -> processData(requestData));
    }
    
    private Object processData(String data) {
        // Implementation omitted
        return new Object();
    }
}

// Example 4: Using prototype scope with CallExecutor in Spring
@Component
@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
class good_case_4 {
    // ok: java-call-executor-not-thread-safe
    private CallExecutor<Integer> retryExecutor = new CallExecutor<>();
    
    public Integer handleRequest(String requestId) {
        return retryExecutor.execute(() -> processRequest(requestId)).getResult();
    }
    
    private Integer processRequest(String requestId) {
        // Implementation omitted
        return 200;
    }
}

// Example 5: Using CallExecutor in a stateful EJB (not singleton)
@Stateful
class good_case_5 {
    // ok: java-call-executor-not-thread-safe
    private CallExecutor<Boolean> executor = new CallExecutor<>();
    
    public Boolean validateWithRetry(String input) {
        return executor.execute(() -> validate(input)).getResult();
    }
    
    private Boolean validate(String input) {
        // Implementation omitted
        return true;
    }
}

// Example 6: Factory method creating new CallExecutor instances
class good_case_6 {
    // ok: java-call-executor-not-thread-safe
    public CallExecutor<String> createExecutor() {
        RetryConfig config = new RetryConfigBuilder()
                .retryOnAnyException()
                .withMaxNumberOfTries(3)
                .build();
        return new CallExecutorBuilder().config(config).build();
    }
    
    public String executeTask(Callable<String> task) {
        CallExecutor<String> executor = createExecutor();
        return executor.execute(task).getResult();
    }
}

// Example 7: Using ThreadLocal to maintain thread-safe CallExecutor instances
class good_case_7 {
    // ok: java-call-executor-not-thread-safe
    private ThreadLocal<CallExecutor<Long>> executorThreadLocal = ThreadLocal.withInitial(() -> new CallExecutor<>());
    
    public Long executeWithRetry(Callable<Long> task) {
        return executorThreadLocal.get().execute(task).getResult();
    }
}

// Example 8: Using CallExecutor in a stateless EJB
@Stateless
class good_case_8 {
    // ok: java-call-executor-not-thread-safe
    private CallExecutor<Double> executor = new CallExecutor<>();
    
    public Double calculateWithRetry(Callable<Double> calculation) {
        return executor.execute(calculation).getResult();
    }
}

// Example 9: Using request scope with CallExecutor in Spring
@Component
@Scope(value = org.springframework.web.context.WebApplicationContext.SCOPE_REQUEST)
class good_case_9 {
    // ok: java-call-executor-not-thread-safe
    private CallExecutor<byte[]> executor = new CallExecutor<>();
    
    public byte[] fetchDataWithRetry(String url) {
        return executor.execute(() -> fetchBinaryData(url)).getResult();
    }
    
    private byte[] fetchBinaryData(String url) {
        // Implementation omitted
        return new byte[0];
    }
}

// Example 10: Creating CallExecutor on demand in a factory method
class good_case_10 {
    // ok: java-call-executor-not-thread-safe
    public <T> T executeWithRetry(Callable<T> task) {
        CallExecutor<T> executor = new CallExecutor<>();
        return executor.execute(task).getResult();
    }
}

// Example 11: Using AsyncCallExecutor in a Spring service
@Service
class good_case_11 {
    // ok: java-call-executor-not-thread-safe
    private AsyncCallExecutor<String> executor = new AsyncCallExecutor<>();
    
    public java.util.concurrent.CompletableFuture<Status<String>> processWithRetry(String input) {
        return executor.execute(() -> process(input));
    }
    
    private String process(String input) {
        // Implementation omitted
        return "processed: " + input;
    }
}

// Example 12: Using session scope with CallExecutor in Spring
@Component
@Scope(value = org.springframework.web.context.WebApplicationContext.SCOPE_SESSION)
class good_case_12 {
    // ok: java-call-executor-not-thread-safe
    private CallExecutor<Integer> executor = new CallExecutor<>();
    
    public Integer computeWithRetry(int value) {
        return executor.execute(() -> compute(value)).getResult();
    }
    
    private Integer compute(int value) {
        // Implementation omitted
        return value * 2;
    }
}

// Example 13: Using AsyncCallExecutor in a CDI singleton
@javax.inject.Singleton
class good_case_13 {
    // ok: java-call-executor-not-thread-safe
    private AsyncCallExecutor<Boolean> executor = new AsyncCallExecutor<>();
    
    public java.util.concurrent.CompletableFuture<Status<Boolean>> checkWithRetry(String data) {
        return executor.execute(() -> check(data));
    }
    
    private Boolean check(String data) {
        // Implementation omitted
        return data != null && !data.isEmpty();
    }
}

// Example 14: Using CallExecutor in a non-singleton class
class good_case_14 {
    // ok: java-call-executor-not-thread-safe
    private CallExecutor<Float> executor = new CallExecutor<>();
    
    public Float calculateWithRetry(Callable<Float> calculation) {
        return executor.execute(calculation).getResult();
    }
}

// Example 15: Using dependency injection to provide new CallExecutor instances
@Configuration
class good_case_15 {
    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    // ok: java-call-executor-not-thread-safe
    public CallExecutor<String> callExecutor() {
        RetryConfig config = new RetryConfigBuilder()
                .retryOnAnyException()
                .withMaxNumberOfTries(5)
                .withExponentialBackoff()
                .build();
        return new CallExecutorBuilder().config(config).build();
    }
    
    @Component
    public static class Service {
        private final CallExecutor<String> executor;
        
        public Service(CallExecutor<String> executor) {
            this.executor = executor;
        }
        
        public String executeWithRetry(String input) {
            return executor.execute(() -> processData(input)).getResult();
        }
        
        private String processData(String input) {
            // Implementation omitted
            return "processed: " + input;
        }
    }
}